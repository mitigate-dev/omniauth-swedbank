# Migration Guide: v008 to v009

## Deadline

Swedbank will shut down banklink protocol v008 on **2026-06-02**. After this date, all v008 authentication requests will be rejected by the bank.

## What Changed in v009

| Aspect | v008 | v009 |
|--------|------|------|
| Signing algorithm | SHA-1 | SHA-512 |
| Request service code | 4002 | 4012 |
| Response service code | 3003 | 3013 |
| VK_SND_ID in response | HP | SWEDBANK_LV |
| Bank certificate | Country-specific (LV) | Unified Baltic |
| Min. key strength | 1024 bits | 2048 bits (recommended 4096) |
| Response user data | VK_INFO (combined string) | VK_USER_NAME, VK_USER_ID, VK_COUNTRY, VK_OTHER, VK_TOKEN |
| New request fields | - | VK_DATETIME, VK_RID |

## Migration Steps

### 1. Update the gem

```bash
bundle update omniauth-swedbank
```

With the default configuration (`version: '008'`), everything continues to work as before. You will see a deprecation warning in logs.

### 2. Download the new bank certificate

The v009 protocol uses a new unified Baltic certificate. Download it from:

https://banklink.swedbank.com/public/resources/bank-certificates/009

Replace your existing Swedbank public certificate file with the new one.

### 3. Check your private key

Your RSA private key must be at least **2048 bits** (recommended: **4096 bits**). Keys must be regenerated every **24 months**. Check your key size with:

```bash
openssl rsa -in your_private_key.pem -text -noout | head -1
```

If it shows less than 2048 bits or is older than 2 years, generate a new keypair via the "Update key" functionality in the [Swedbank Solution support page](https://www.swedbank.lv/business/cash/banklink/integrate).

### 4. Update your provider configuration

```ruby
# Before (v008 - default)
provider :swedbank,
  File.read("path/to/private.key"),
  File.read("path/to/old_bank.crt"),
  ENV['SWEDBANK_SND_ID'],
  ENV['SWEDBANK_REC_ID']

# After (v009)
provider :swedbank,
  File.read("path/to/private.key"),
  File.read("path/to/new_baltic_bank.crt"),
  ENV['SWEDBANK_SND_ID'],
  ENV['SWEDBANK_REC_ID'],
  version: '009'
```

### 5. Update your callback handling (if applicable)

If your application reads user data from the auth hash, note these changes:

**v008:** User ID and name were parsed from the `VK_INFO` field (`ISIK:123456-12345;NIMI:John Doe`).

**v009:** User data comes in separate fields:
- `auth.uid` - reads from `VK_USER_ID` directly
- `auth.info.full_name` - reads from `VK_USER_NAME` directly  
- `auth.info.country` - new field from `VK_COUNTRY` (e.g., `LV`)
- `auth.extra.raw_info` - contains all response parameters including `VK_TOKEN`, `VK_OTHER`, `VK_RID`

If you only use `auth.uid` and `auth.info.full_name`, no changes are needed in your application code.

## Reference

- [Swedbank comparison PDF](https://www.swedbank.lv/static/business/banklink/LV_Authentication_008_vs_009_instruction.pdf)
- [Bank certificates for v009](https://banklink.swedbank.com/public/resources/bank-certificates/009)
