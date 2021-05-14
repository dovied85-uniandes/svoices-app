web: gunicorn api.wsgi:app
worker: celery -A batch.transcoder worker
beat: celery -A batch.transcoder beat
clock: python autoscaler/autoscale.py
