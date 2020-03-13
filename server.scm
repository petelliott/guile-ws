(define-module (guile-ws server)
  #:use-module (web server)
  #:use-module (web request)
  #:export (hijack-port
            close-response
            hijack-request))

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
