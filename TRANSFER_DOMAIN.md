Akamai Linode is **not a domain registrar**, so you cannot transfer your domain registration or ownership directly to Linode. Your domain will remain registered at World.com (or whichever registrar holds the registration), but you can host your website and manage your DNS using Akamai Cloud Manager.

To point your domain registered at World.com to your Akamai Linode server or manage its DNS records in Linode's Cloud Manager, follow these steps:

1. **Create a Domain Zone in Linode Cloud Manager:**
   Log in to **Akamai Cloud Manager**, navigate to **Domains** in the left sidebar, and click **Create Domain** (or **Import a Zone** if you want to import existing records). Select **Master**, enter your domain name, enter an admin email address, and choose default records or associate it with your target Linode instance.


2. **Configure DNS Records in Linode:**
   Inside your newly created Domain Zone in Linode, add or edit the necessary records:

* **A Record:** Point `@` (and `www`) to your Linode instance's IPv4 address.
* **AAAA Record:** Point to your Linode's IPv6 address if applicable.
* **MX / TXT Records:** Add any mail or verification records if you host email.


3. **Update Nameservers at World.com:**
   Log into your control panel at **World.com** and locate the **Nameserver Settings** for your domain. Replace the existing nameservers with Akamai Linode's official authority nameservers:

* `ns1.linode.com`
* `ns2.linode.com`
* `ns3.linode.com`
* `ns4.linode.com`
* `ns5.linode.com`


4. **Verify Propagation:**
   Save your changes at World.com. DNS propagation can take anywhere from a few minutes up to 24–48 hours globally. You can verify the progress using CLI tools like `dig world.com NS` or online lookup tools like DNSChecker.


---

### Alternative: Keep DNS at World.com

If you prefer to keep managing DNS records inside World.com's dashboard rather than using Linode's DNS Manager, you don't need to change nameservers. Simply stay in World.com's DNS settings and edit your **A** and **AAAA** records directly to point to your Linode compute instance's public IP address.