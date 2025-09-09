# Basic check
whois aigf.art | grep -E "(Creation Date|Registrant|Registrar)"

# More detailed analysis
whois aigf.art | grep -E "(Creation|Registrant|Admin|Tech|Registrar|Name Server)" 

# # Check multiple domains
# for domain in domain1.com domain2.net domain3.org; do
#     echo "=== $domain ==="
#     whois $domain | grep -E "(Creation Date|Registrant Organization)"
#     echo
# done
