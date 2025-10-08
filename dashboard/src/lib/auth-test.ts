// Test utility for authentication endpoints
// This file can be used for testing the auth functionality

import { authClient } from './auth';

export async function testOTPFlow() {
    try {
        console.log('Testing OTP flow...');

        // Test sending login OTP
        console.log('1. Sending login OTP...');
        await authClient.sendOTP({
            recipient: 'test@example.com',
            type: 'email',
            purpose: 'login'
        });
        console.log('✅ Login OTP sent successfully');

        // Test sending registration OTP
        console.log('2. Sending registration OTP...');
        await authClient.sendOTP({
            recipient: 'newuser@example.com',
            type: 'email',
            purpose: 'registration'
        });
        console.log('✅ Registration OTP sent successfully');

        // Test sending verification OTP
        console.log('3. Sending verification OTP...');
        await authClient.sendOTP({
            recipient: 'verify@example.com',
            type: 'email',
            purpose: 'verification'
        });
        console.log('✅ Verification OTP sent successfully');

        console.log('🎉 All OTP tests passed!');

    } catch (error) {
        console.error('❌ OTP test failed:', error);
    }
}

export async function testSMSOTPFlow() {
    try {
        console.log('Testing SMS OTP flow...');

        // Test sending SMS login OTP
        console.log('1. Sending SMS login OTP...');
        await authClient.sendOTP({
            recipient: '+233123456789',
            type: 'sms',
            purpose: 'login'
        });
        console.log('✅ SMS Login OTP sent successfully');

        console.log('🎉 SMS OTP test passed!');

    } catch (error) {
        console.error('❌ SMS OTP test failed:', error);
    }
}

// Example usage:
// testOTPFlow();
// testSMSOTPFlow();