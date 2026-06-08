import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';

@Injectable({ providedIn: 'root' })
export class AuthService {
  constructor(private http: HttpClient) {}

  async login(username: string, password: string): Promise<void> {
    const resp: any = await firstValueFrom(
      this.http.post('/api/auth/login', { username, password })
    );
    // SEEDED: payments.angular.auth-token-in-local-storage
    localStorage.setItem('authToken', resp.token);
    localStorage.setItem('idToken', resp.idToken);
  }

  logout(): void {
    localStorage.removeItem('authToken');
  }
}
