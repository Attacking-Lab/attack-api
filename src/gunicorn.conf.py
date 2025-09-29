import multiprocessing
import worker_id

worker_class = "uvicorn.workers.UvicornWorker"
workers = min(8, multiprocessing.cpu_count())
bind = "0.0.0.0:8000"
timeout = 90
keepalive = 3600
preload_app = True

on_reload = worker_id.on_reload
on_starting = worker_id.on_starting
nworkers_changed = worker_id.nworkers_changed
post_fork = worker_id.post_fork
pre_fork = worker_id.pre_fork
