(define-module (guile-ws server)
  #:use-module (web server)
  #:use-module (web request)
  #:use-module (web response)
  #:export (hijack-port
            close-response
            hijack-request
            ws-verify-request
            ws-built-response
            ws-upgrade))

(define (hijack-port port)
  "steals a port, replacing other instances with a /dev/null port"
  (force-output port)
  (let ((newport (dup port))
        (devnull (open "/dev/null" O_RDWR)))
    (redirect-port devnull port)
    (close-port devnull)
    newport))

(define (close-response)
  "returns a response that ensures the connection will be closed"
  (values '((connection . (close)))
          #f))

(define (hijack-request request)
  "steals the port from an http request, such that it will remain
   open and not be closed by the webserver"
  (hijack-port (request-port request)))

(define (ws-verify-request request)
  "returns #f if the request is not a valid websocket handshake
   request"
  (define headers (request-headers request))
  (and
   (equal? (assoc-ref headers 'upgrade) '("websocket"))
   (equal? (assoc-ref headers 'connection) '(upgrade))
   (assoc-ref headers 'sec-websocket-key)
   (equal? (assoc-ref headers 'sec-websocket-version) "13")))

(define (ws-error-response)
  "the response that is sent when a client's handshake is invalid"
  (values
   (build-response #:code 400
                   #:headers '((content-type . (text/plain))))
   "Invalid client websocket handshake"))

(define* (ws-build-response request #:optional (headers '()))
  "build a server's websocket handshake response"
  (build-response #:code 101
                  #:headers `((upgrade . ("websocket"))
                              (connection . (upgrade))
                              (sec-websocket-accept . "TODO")
                              ,@headers)))

(define (ws-upgrade request fun)
  "upgrades to a websocket and calls fun with the ws as the argument"
  (if (not (ws-verify-request request))
      (ws-error-response)
      (let ((port (hijack-request request)))
        (write-response (ws-build-response request) port)
        (fun port)
        (close-response))))
