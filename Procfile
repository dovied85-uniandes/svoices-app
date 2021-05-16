web: gunicorn api.wsgi:app
worker: celery -A batch.transcoder worker
clock: python autoscaler/autoscale.py
