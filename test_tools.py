from tools import search_policies, create_ticket, send_email

print(search_policies("password"))
print(create_ticket("Test ticket", "low"))
send_email("someone@example.com", "Hello")