# DEK Creation Isolation Fix Plan

## 1. Issue Description

When attempting to generate a Data Encryption Key (DEK) for a specific organization via the API endpoint `/api/v1/organizations/settings/encryption/dek/generate`, the following error occurs:

```json
{
  "error": "Failed to create DEK: failed to create DEK: DEK already active in service state for scope organization/<orgID>",
  "success": false
}
```

This happens even if no DEK exists for that specific organization, particularly if the system-level DEK is already active. This indicates a lack of proper isolation between the system scope and organization scopes within the DEK creation logic.

## 2. Analysis

The root cause was identified in the `dekService.CreateDEK` function within `dek/service.go`.

- **Problematic Code:** Lines 591-597 perform an initial check against the service instance's internal state (`s.info`):

  ```go
  // Quick check if we *know* a DEK exists internally
  currentInfo := s.info // Copy pointer under lock
  s.mu.RUnlock()        // Release RLock

  if currentInfo != nil && currentInfo.Active {
      return nil, fmt.Errorf("DEK already active in service state for scope %s/%s", scope, orgID)
  }
  ```

- **Why it's wrong:** This check uses the `s.info` field, which caches the last loaded/created DEK info for _that specific service instance_. If the same `dekService` instance is used to handle both system (`scope="system"`) and organization (`scope="organization"`) requests, `s.info` might hold the system DEK details. When `CreateDEK` is then called for an organization, this check incorrectly identifies the cached _system_ DEK as being active for the _organization_ scope, leading to the premature error.
- **Correct Check:** The subsequent code block (lines 599-610) correctly queries the persistent data store (`s.store.GetActiveDEK`) using the specific `scope` and `orgID` passed into the function. This check accurately determines if a DEK _already exists for the target scope/orgID_ in the database.
  ```go
  // Now check the persistent store definitively WITHOUT holding the main service lock
  s.zLogger.Debug().Str("scope", scope).Str("orgID", orgID).Msg("Checking store for existing active DEK before creation")
  existingInfo, err := s.store.GetActiveDEK(ctx, scope, orgID)
  // ... error handling ...
  else if existingInfo != nil {
      s.zLogger.Warn().Str("scope", scope).Str("orgID", orgID).Str("existingDEKId", existingInfo.Id).Msg("DEK already exists in store")
      return nil, fmt.Errorf("DEK already exists in store for scope %s/%s", scope, orgID)
  }
  ```
- **Caching:** Analysis of `cache/dek.go` and the key generation functions (`getCacheKey`, `getUnwrappedCacheKey`) in `dek/service.go` confirmed that cache keys _are_ correctly generated with scope and orgID, so the caching mechanism itself is not the cause of the isolation issue.

## 3. Proposed Solution

Remove the initial, incorrect check against the internal `s.info` state (lines 591-597 in `dek/service.go`). The function should rely _solely_ on the subsequent check against the persistent store (lines 599-610), which correctly uses the provided `scope` and `orgID` to determine if a DEK already exists for that specific context before attempting creation.

## 4. Conceptual Flow Change

```mermaid
graph TD
    A[CreateDEK called with scope, orgID] --> B{Check s.info (Internal State)};
    B -- DEK Active --> C[Return Error: "DEK already active"];
    B -- DEK Not Active --> D{Check Store for scope/orgID};
    D -- Exists in Store --> E[Return Error: "DEK already exists"];
    D -- Not in Store --> F[Proceed with DEK Generation];

    subgraph "Proposed Change"
        direction TB
        A_new[CreateDEK called with scope, orgID] --> D_new{Check Store for scope/orgID};
        D_new -- Exists in Store --> E_new[Return Error: "DEK already exists"];
        D_new -- Not in Store --> F_new[Proceed with DEK Generation];
    end
```

## 5. Next Steps

Implement the code change by removing lines 591-597 from `dek/service.go`.
