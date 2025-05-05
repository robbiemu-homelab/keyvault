# Search Box User Guide

This guide shows you how to craft effective queries in the search box for secrets in the keyvault. The keyvault is a simple key:value pairing supporting json in the value position. The special fields "secret_key" and "secret value" reflect these basic properties, if you need to be very specific about your search.

## 1. Simple Keywords
Type any word to find items containing it.

- **Example**: `error` finds all secrets with “error.”

## 2. Exact Phrases
Enclose text in double quotes to search as a single phrase.

- **Example**: `"hello world"` matches the exact phrase “hello world.”

## 3. Excluding Terms
Prefix a word or phrase with a minus sign (`-`) to exclude it.

- **Example**: `error -debug` finds secrets with “error” but without “debug.”

## 4. Combining Conditions
- **Default AND**: Multiple terms are implicitly ANDed.
  - `apple banana` finds items containing both “apple” and “banana.”
- **OR Operator**: Use `OR` (uppercase) between terms to allow either.
  - `error OR warning` finds items with either “error” or “warning.”

## 5. Field Filters
Limit search to a specific field using `field:value`.

- **Example**: `status:open priority:high` finds items where `status` is “open” AND `priority` is “high.”
- Field names are case-insensitive; values that include spaces must be quoted:
  - `"user name":"John Doe"`

### Special Field Filters (`secret_key` and `secret_value`):
Use these for precise searches targeting only the key name or only the value content.
-   `secret_key:<value>`: Searches **only** the `secret_key` column for the specified `<value>`.
    -   **Example**: `secret_key:api_token` finds secrets where the key name itself contains "api\_token". It does *not* search the value.
-   `secret_value:<value>`: Searches **only** the text content of the `secret_value` column for the specified `<value>`.
    -   **Example**: `secret_value:"database error"` finds secrets where the value contains the phrase "database error". It does *not* search the key name.

## 6. Grouping with Parentheses
Use parentheses `()` to combine filters and operators in complex searches.

- **Example**: `(error OR warning) -debug` finds secrets with “error” or “warning” but no “debug.”

## 7. Tips for Effective Searching
- **Wildcard Searches**: Append `*` to a partial term to match prefixes (if supported).
- **Case Insensitivity**: Searches ignore letter case by default.
- **Whitespace**: Extra spaces are ignored; focus on logical structure.

## 8. Example Queries
| Query                                   | Finds…                                                            |
|-----------------------------------------|-------------------------------------------------------------------|
| `login failed`                         | secrets containing both “login” and “failed.”                     |
| `"server error"`                     | secrets containing the exact phrase “server error.”               |
| `status:closed -"user error"`        | Closed secrets without the phrase “user error.”                  |
| `priority:low OR priority:medium`      | secrets with either low or medium priority.                      |
| `(status:open OR status:pending) assigned:alice` | Open or pending secrets assigned to Alice.            |

With these simple patterns, you can quickly zero in on the data you need in the search box.

