from django.db import models

class RequestLog(models.Model):
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(auto_now_add=True)
    path = models.CharField(max_length=255)
    
    def __str__(self):
        return f"{self.ip_address} at {self.timestamp} on {self.path}"

# ip_tracking/middleware.py
from .models import RequestLog
from django.utils.deprecation import MiddlewareMixin
from ipware import get_client_ip

class IPLoggingMiddleware(MiddlewareMixin):
    def process_request(self, request):
        ip, is_routable = get_client_ip(request)
        if ip is None:
            ip = '0.0.0.0'
        RequestLog.objects.create(ip_address=ip, path=request.path)

class BlockedIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    
    def __str__(self):
        return self.ip_address

# ip_tracking/middleware.py (update)
from .models import BlockedIP
from django.http import HttpResponseForbidden

class IPLoggingMiddleware(MiddlewareMixin):
    def process_request(self, request):
        ip, is_routable = get_client_ip(request)
        if ip is None:
            ip = '0.0.0.0'
        # Check blacklist
        if BlockedIP.objects.filter(ip_address=ip).exists():
            return HttpResponseForbidden('Forbidden: Your IP is blacklisted.')
        RequestLog.objects.create(ip_address=ip, path=request.path)

# ip_tracking/management/commands/block_ip.py
from django.core.management.base import BaseCommand
from ip_tracking.models import BlockedIP

class Command(BaseCommand):
    help = 'Block an IP address by adding it to the BlockedIP model.'

    def add_arguments(self, parser):
        parser.add_argument('ip_address', type=str, help='IP address to block')

    def handle(self, *args, **options):
        ip = options['ip_address']
        BlockedIP.objects.get_or_create(ip_address=ip)
        self.stdout.write(self.style.SUCCESS(f"IP address {ip} has been blocked."))

class RequestLog(models.Model):
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(auto_now_add=True)
    path = models.CharField(max_length=255)
    country = models.CharField(max_length=100, null=True, blank=True)
    city = models.CharField(max_length=100, null=True, blank=True)

# ip_tracking/middleware.py (update)
import requests
from django.core.cache import cache

class IPLoggingMiddleware(MiddlewareMixin):
    def process_request(self, request):
        ip, is_routable = get_client_ip(request)
        if ip is None:
            ip = '0.0.0.0'
        if BlockedIP.objects.filter(ip_address=ip).exists():
            return HttpResponseForbidden('Forbidden: Your IP is blacklisted.')

        geo_data = cache.get(ip)
        if not geo_data:
            try:
                response = requests.get(f"https://ipinfo.io/{ip}/json")
                data = response.json()
                geo_data = {
                    'country': data.get('country', ''),
                    'city': data.get('city', ''),
                }
                cache.set(ip, geo_data, 86400)  # cache for 24 hours
            except Exception:
                geo_data = {'country': '', 'city': ''}

        RequestLog.objects.create(
            ip_address=ip,
            path=request.path,
            country=geo_data['country'],
            city=geo_data['city']
        )


class SuspiciousIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    reason = models.TextField()

    def __str__(self):
        return f"Suspicious IP: {self.ip_address} ({self.reason})"

# ip_tracking/tasks.py
from celery import shared_task
from django.utils import timezone
from datetime import timedelta
from .models import RequestLog, SuspiciousIP

@shared_task
def detect_anomalies():
    one_hour_ago = timezone.now() - timedelta(hours=1)
    suspicious_ips = (
        RequestLog.objects
        .filter(timestamp__gte=one_hour_ago)
        .values('ip_address')
        .annotate(request_count=models.Count('id'))
        .filter(request_count__gt=100)
    )
    for entry in suspicious_ips:
        ip = entry['ip_address']
        SuspiciousIP.objects.get_or_create(ip_address=ip, reason='Excessive requests in the last hour')

    sensitive_paths = ['/admin', '/login']
    sensitive_logs = RequestLog.objects.filter(timestamp__gte=one_hour_ago, path__in=sensitive_paths)
    for log in sensitive_logs:
        SuspiciousIP.objects.get_or_create(ip_address=log.ip_address, reason=f"Accessed sensitive path: {log.path}")

# Final Note:
# - Add 'ip_tracking.middleware.IPLoggingMiddleware' to MIDDLEWARE in settings.py.
# - Schedule detect_anomalies Celery task hourly.
# - Ensure ipware, django-ratelimit, celery, and ipinfo dependencies are installed.

# This completes your Milestone 6 deliverables cleanly, ready for commit and push.
