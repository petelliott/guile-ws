(define-module (guile-ws connection)
  #:use-module (srfi srfi-9)
  #:use-module (srfi srfi-11)
  #:use-module ((rnrs io ports)
                #:select (put-u8 put-bytevector get-u8 get-bytevector-n))
  #:use-module (rnrs bytevectors)
  #:use-module (ice-9 iconv)
  #:export (make-ws
            ws?
            ws-port
            ws-state
            set-ws-state!
            ws-masked?
            make-ws-frame
            ws-frame?
            ws-frame-opcode
            ws-frame-mask
            ws-frame-body
            ws:CONT
            ws:TEXT
            ws:BIN
            ws:CLOSE
            ws:PING
            ws:PONG
            read-ws-frame
            write-ws-frame
            ws-loop
            ws-send
            ws-close))

(define-record-type <ws>
  (make-ws port state masked)
  ws?
  (port ws-port)
  (state ws-state set-ws-state!)
  (masked ws-masked?))

;; TODO fragmentation
(define-record-type <ws-frame>
  (make-ws-frame opcode mask body)
  ws-frame?
  (opcode ws-frame-opcode)
  (mask ws-frame-mask)
  (body ws-frame-body))

(define ws:CONT  #x0)
(define ws:TEXT  #x1)
(define ws:BIN   #x2)
(define ws:CLOSE #x8)
(define ws:PING  #x9)
(define ws:PONG  #x9)

(define (get-u16 port)
  (logior
   (ash (get-u8 port) 8)
   (get-u8 port)))

(define (get-u32 port)
  (logior
   (ash (get-u8 port) 24)
   (ash (get-u8 port) 16)
   (ash (get-u8 port) 8)
   (get-u8 port)))

(define (get-u64 port)
  (logior
   (ash (get-u8 port) 56)
   (ash (get-u8 port) 48)
   (ash (get-u8 port) 40)
   (ash (get-u8 port) 32)
   (ash (get-u8 port) 24)
   (ash (get-u8 port) 16)
   (ash (get-u8 port) 8)
   (get-u8 port)))

(define (u32-swap-endianness u32)
  (logior
   (ash (logand u32 #xff) 24)
   (ash (logand u32 #xff00) 8)
   (ash (logand u32 #xff0000) -8)
   (ash (logand u32 #xff000000) -24)))

(define (mask! bv mask)
  "applies mask to bytevector (note that this is the same as in
   reverse)"
  (when mask
    (let ((rmask (u32-swap-endianness mask)))
      (array-index-map!
       bv
       (lambda (i)
         (logxor (array-ref bv i)
                 (logand (ash rmask (* -8 (modulo i 4))) #xff))))))
  bv)

(define (read-len-mask port)
  (define fbyte (get-u8 port))
  (define maskbit (ash fbyte -7))
  (define len (logand fbyte #x7f))
  (values
   (cond
    ((= len 126) (get-u16 port))
    ((= len 127) (get-u64 port))
    (else len))
   (if (= maskbit 1)
       (get-u32 port)
       #f)))

(define (unsanitize-body opcode body)
  (cond
   ((= opcode ws:TEXT) (bytevector->string body "UTF-8"))
   ((= opcode ws:CLOSE)
    (cons
     (logior (ash (array-ref body 0) 8)
             (array-ref body 1))
     ;; this takes 2 copies when it should do 0
     (let* ((mlen (- (bytevector-length body) 2))
            (bv (make-bytevector mlen)))
       (bytevector-copy! body 2 bv 0 mlen)
       (bytevector->string bv "UTF-8"))))
   (else body)))

(define (read-ws-frame port)
  (define fbyte (get-u8 port))
  ;;;TODO: check FIN bit
  (if (eof-object? fbyte)
      fbyte
      (let*-values (((opcode) (logand fbyte #xf))
                    ((len mask) (read-len-mask port))
                    ((body) (get-bytevector-n port len)))
        (make-ws-frame opcode mask
                       (unsanitize-body opcode (mask! body mask))))))


(define (put-u16 port val)
  (put-u8 port (ash val -8))
  (put-u8 port (logand val #xff)))

(define (put-u64 port val)
  (put-u8 port (logand (ash val -56) #xff))
  (put-u8 port (logand (ash val -48) #xff))
  (put-u8 port (logand (ash val -40) #xff))
  (put-u8 port (logand (ash val -32) #xff))
  (put-u8 port (logand (ash val -24) #xff))
  (put-u8 port (logand (ash val -16) #xff))
  (put-u8 port (logand (ash val -8) #xff))
  (put-u8 port (logand val #xff)))

(define (sanitize-body frame)
  (define opcode (ws-frame-opcode frame))
  (define body (ws-frame-body frame))
  (cond
   ((= opcode ws:TEXT) (string->bytevector body "UTF-8"))
   ((= opcode ws:CLOSE)
    (let* ((code (car body))
           (msg (string->bytevector (cdr body) "UTF-8"))
           (mlen (bytevector-length msg))
           (body (make-bytevector (+ mlen 2))))
      (array-set! body (ash code -8) 0)
      (array-set! body (logand code #xff) 1)
      (bytevector-copy! msg 0 body 2 mlen)
      body))
   (else body)))

(define (write-ws-frame frame port)
  (let* ((body (sanitize-body frame))
         (len (bytevector-length body)))
    (put-u8 port (logior #x80 (ws-frame-opcode frame)))
    ;; TODO set mask bit
    (cond
     ((< len 126)
      (put-u8 port len))
     ((< len (expt 2 16))
      (put-u8 port 126)
      (put-u16 port len))
     (else
      (put-u8 port 127)
      (put-u64 port len)))
    ;;TODO send mask key
    (put-bytevector port body)
    (force-output port)))

;;; The following is the recomended public api

(define (ws-loop ws proc)
  "calls proc with each incoming message from ws. returns the close
   code and reason"
  (define frame (read-ws-frame (ws-port ws)))
  (cond
   ((eof-object? frame) (values 1006 "")) ; 1006: abnormal closure, never sent
   ((= (ws-frame-opcode frame) ws:CLOSE)
    (when (eq? (ws-state ws) 'OPEN)
      ;; TODO fix for masked websockets
      (write-ws-frame (make-ws-frame ws:CLOSE #f (ws-frame-body frame))
                      (ws-port ws)))
    (close-port (ws-port ws))
    (set-ws-state! ws 'CLOSED)
    (values (car (ws-frame-body frame))
            (cdr (ws-frame-body frame))))
   (else
    (proc (ws-frame-body frame))
    (ws-loop ws proc))))

(define (ws-send ws data)
  "send data (bytevector or string) to ws"
  (if (eq? (ws-state ws) 'OPEN)
      (write-ws-frame (make-ws-frame
                       (if (string? data) ws:TEXT ws:BIN)
                       #f data)
                      (ws-port ws))
      (error "attempt to send to non-open websocket" ws)))

(define* (ws-close ws #:optional (code 1000) (reason ""))
  "close ws. subsequet calls will have no effect"
  (when (eq? (ws-state ws) 'OPEN)
    ;; TODO fix for masked websockets
    (write-ws-frame (make-ws-frame ws:CLOSE #f
                                   (cons code reason))
                    (ws-port ws))
    (set-ws-state! ws 'CLOSING)))
