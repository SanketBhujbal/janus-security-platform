import { Component, ElementRef } from '@angular/core';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

@Component({
  selector: 'app-admin',
  template: `<div [innerHTML]="trustedHtml"></div>`,
})
export class AdminComponent {
  trustedHtml: SafeHtml;

  constructor(private sanitizer: DomSanitizer, private host: ElementRef) {
    const userMessage = location.search.split('msg=')[1] ?? '';
    // SEEDED: payments.angular.bypass-security-trust
    this.trustedHtml = this.sanitizer.bypassSecurityTrustHtml(userMessage);
  }

  showCardForDebug(card: { pan: string; cvv: string }) {
    // SEEDED: payments.angular.console-log-card-data
    console.log('admin debug', card.pan, card.cvv);
  }

  renderRaw(input: string) {
    // SEEDED: payments.angular.inner-html-with-user-data
    this.host.nativeElement.innerHTML = input;
  }
}
