from django.http import JsonResponse
from django_ratelimit.decorators import ratelimit
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
@ratelimit(key='ip', rate='10/m', method='POST', block=True)
def login_view(request):
    return JsonResponse({'message': 'Login successful'})

@csrf_exempt
@ratelimit(key='ip', rate='5/m', method='GET', block=True)
def anonymous_view(request):
    return JsonResponse({'message': 'Anonymous access allowed'})
