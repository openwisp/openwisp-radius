from django.contrib.admin.views.decorators import staff_member_required
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect
from django.template.response import TemplateResponse
from payments import RedirectNeeded, get_payment_model
from plans.models import Invoice
from rest_framework.generics import ListAPIView

from .serializers import PlanPricingSerializer, get_plan_pricing_queryset


def payment_details(request, pk):
    payment = get_object_or_404(get_payment_model(), pk=pk)
    try:
        form = payment.get_form(data=request.POST or None)
    except RedirectNeeded as redirect_to:
        return redirect(str(redirect_to))
    return TemplateResponse(request, 'payment.html',
                            {'form': form, 'payment': payment})


@staff_member_required
def download_invoice(request, pk):
    obj = get_object_or_404(Invoice, pk=pk)
    filename = obj.get_invoice_pdf_filename()
    pdf = obj.generate_invoice_pdf()
    response = HttpResponse(pdf.getvalue(), content_type='application/octet-stream')
    response['Content-Disposition'] = 'attachment; filename={0}'.format(filename)
    return response


class PlanPricingView(ListAPIView):
    queryset = get_plan_pricing_queryset()
    serializer_class = PlanPricingSerializer


plan_pricing = PlanPricingView.as_view()
