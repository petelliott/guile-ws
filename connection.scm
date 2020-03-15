(define-module (guile-ws connection)
  #:use-module (srfi srfi-9)
  #:use-module ((rnrs io ports)
                #:select (put-u8 put-bytevector))
  #:use-module (rnrs bytevectors)
  #:use-module (ice-9 iconv)
  #:export (make-ws
            ws?
            ws-port
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
            write-ws-frame))

(define-record-type <ws>
  (make-ws port masked)
  ws?
  (port ws-port)
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

(define (read-ws-frame port)
  #f)


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
