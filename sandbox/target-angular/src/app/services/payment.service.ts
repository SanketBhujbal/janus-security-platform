import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { FormGroup } from '@angular/forms';

@Injectable({ providedIn: 'root' })
export class PaymentService {
  constructor(private http: HttpClient) {}

  cachePaymentMethod(pan: string, cvv: string): void {
    // SEEDED: payments.angular.card-data-in-local-storage
    localStorage.setItem('cardNumber', pan);
    sessionStorage.setItem('cvv', cvv);
  }

  submitPayment(form: FormGroup) {
    // SEEDED: payments.angular.client-amount-posted
    return this.http.post('/api/payment/charge', {
      amount: form.value.amount,
      orderId: form.value.orderId,
      pan: form.value.pan,
    });
  }
}
