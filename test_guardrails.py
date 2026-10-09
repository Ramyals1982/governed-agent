from guardrails import redact

tests = [
    "My phone number is 9876543210. Create a ticket about my lost laptop.",
    "Call me on +91 98765 43210 please",
    "My PAN is ABCDE1234F",
    "Aadhaar 1234 5678 9012",
    "Email the policy to ramya.home@gmail.com",
    "What is our password policy?",
]
for t in tests:
    print(redact(t))