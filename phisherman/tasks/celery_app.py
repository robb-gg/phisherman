"""Celery application configuration and task definitions."""

import logging

from celery import Celery
from celery.schedules import crontab

from phisherman.config import settings

logger = logging.getLogger(__name__)

# Create Celery app
app = Celery("phisherman")

# Configure Celery
app.conf.update(settings.celery_config)

# Periodic task schedule
app.conf.beat_schedule = {
    "refresh-phishtank-feed": {
        "task": "phisherman.tasks.feeds.refresh_phishtank",
        "schedule": crontab(minute=f"*/{settings.phishtank_refresh_interval}"),
    },
    "refresh-openphish-feed": {
        "task": "phisherman.tasks.feeds.refresh_openphish",
        "schedule": crontab(minute=f"*/{settings.openphish_refresh_interval}"),
    },
    "refresh-urlhaus-feed": {
        "task": "phisherman.tasks.feeds.refresh_urlhaus",
        "schedule": crontab(minute=f"*/{settings.urlhaus_refresh_interval}"),
    },
    "cleanup-old-entries": {
        "task": "phisherman.tasks.maintenance.cleanup_old_entries",
        "schedule": crontab(hour=2, minute=0),  # Daily at 2 AM
    },
}

# Auto-discover tasks
app.autodiscover_tasks(
    [
        "phisherman.tasks.feeds",
        "phisherman.tasks.maintenance",
    ]
)

if __name__ == "__main__":
    app.start()
