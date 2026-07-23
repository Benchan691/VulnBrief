bind = '0.0.0.0:9100'

# `create_app()` starts the operations/newsletter scheduler in-process.  Keep a
# single worker process so deploying more HTTP capacity cannot start duplicate
# schedulers, while gthread lets normal requests continue when a client stalls
# before sending a complete HTTP request.
workers = 1
worker_class = 'gthread'
threads = 4

# The thread worker continues to notify Gunicorn while an individual client is
# slow, so an incomplete request no longer causes the whole web service to be
# recycled.  Keep idle persistent connections short.
timeout = 30
graceful_timeout = 30
keepalive = 5
