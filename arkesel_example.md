### Arkesel Eample with TS
```ts

// Arkesel SMS API Integration for Ghana
// Documentation: https://developers.arkesel.com/sms/v2/

interface ArkeselSMSResponse {
    status: string
    message?: string
    data?: any
}

interface SendSMSParams {
    recipient: string
    sender: string
    message: string
}

class ArkeselSMSService {
    private apiKey: string
    private baseUrl: string = 'https://sms.arkesel.com/api/v2/sms'

    constructor(apiKey: string) {
        this.apiKey = apiKey
    }

    /**
     * Send SMS using Arkesel API
     * @param params SMS parameters
     * @returns Promise with API response
     */
    async sendSMS(params: SendSMSParams): Promise<ArkeselSMSResponse> {
        try {
            const response = await fetch(`${this.baseUrl}/send`, {
                method: 'POST',
                headers: {
                    'api-key': this.apiKey,
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    sender: params.sender,
                    message: params.message,
                    recipients: [params.recipient],
                }),
            })

            const data = await response.json()

            if (!response.ok) {
                throw new Error(`Arkesel API Error: ${data.message || 'Unknown error'}`)
            }

            return data
        } catch (error) {
            console.error('Arkesel SMS Error:', error)
            throw error
        }
    }

    /**
     * Send OTP SMS
     * @param phoneNumber Phone number in international format (e.g., +233XXXXXXXXX)
     * @param otp 6-digit OTP code
     * @param appName Application name for branding
     * @returns Promise with API response
     */
    async sendOTP(phoneNumber: string, otp: string, appName: string = 'QuickBite'): Promise<ArkeselSMSResponse> {
        // Format phone number for Ghana (remove + and ensure it starts with 233)
        const formattedPhone = this.formatGhanaianNumber(phoneNumber)

        const message = `Your ${appName} verification code is: ${otp}. This code expires in 5 minutes. Do not share this code with anyone.`

        return this.sendSMS({
            recipient: formattedPhone,
            sender: appName.substring(0, 11), // Arkesel sender ID max 11 characters
            message,
        })
    }

    /**
     * Format phone number for Ghanaian numbers
     * @param phoneNumber Phone number in various formats
     * @returns Formatted phone number for Arkesel API
     */
    private formatGhanaianNumber(phoneNumber: string): string {
        // Remove all non-digit characters
        let cleaned = phoneNumber.replace(/\D/g, '')

        // Handle different formats
        if (cleaned.startsWith('233')) {
            return cleaned
        } else if (cleaned.startsWith('0')) {
            return '233' + cleaned.substring(1)
        } else if (cleaned.length === 9) {
            return '233' + cleaned
        }

        return cleaned
    }

    /**
     * Check account balance
     * @returns Promise with balance information
     */
    async getBalance(): Promise<ArkeselSMSResponse> {
        try {
            const response = await fetch(`https://sms.arkesel.com/api/v2/clients/balance-details`, {
                method: 'GET',
                headers: {
                    'api-key': this.apiKey,
                },
            })

            const data = await response.json()

            if (!response.ok) {
                throw new Error(`Arkesel API Error: ${data.message || 'Unknown error'}`)
            }

            return data
        } catch (error) {
            console.error('Arkesel Balance Check Error:', error)
            throw error
        }
    }
}

// Export singleton instance
export const arkeselSMS = new ArkeselSMSService(
    process.env.ARKESEL_API_KEY || 'd21QRVFoSXFGbUdxQW1tSXFxWUs'
)

export default ArkeselSMSService
```