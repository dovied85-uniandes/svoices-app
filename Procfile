web: gunicorn api.wsgi:app
worker: celery -A batch.transcoder worker --beat
clock: python autoscaler/autoscale.py
