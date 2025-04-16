# CoreEncryptionService Refactoring Plan

## Goal

To eliminate the dependency on a global `dekService` instance and ensure that encryption operations for different scopes (system vs. organization) are handled by correctly configured, isolated service instances. This involves making `CoreEncryptionService` responsible for managing its own scope-specific `dekService`.

## Problem

The current implementation relies on a global `dek.GetService()` which returns a singleton `dekService` instance initialized only for the system scope. This prevents correct handling of organization-specific DEK operations (creation, rotation, status checks) as the underlying KMS provider logic is tied to the system configuration, leading to errors like "KMS provider is not configured for scope 'organization'".

## Proposed Changes

1.  **Modify `CoreEncryptionService` Struct (`internal/encryption/settings/core_service.go`):**

    - Add a field to hold the dedicated `dekService` instance: `dekService encInterfaces.DEKService`.
    - Re-add fields for caching KMS providers per scope (this logic needs to live here as `CoreEncryptionService` implements the getter):
      - `kmsCacheMutex sync.RWMutex`
      - `kmsProviderCache map[string]encInterfaces.KMSProvider`

2.  **Modify `NewCoreEncryptionService` (`internal/encryption/settings/core_service.go`):**

    - Initialize the `kmsProviderCache`: `kmsProviderCache: make(map[string]encInterfaces.KMSProvider)`.
    - Inside the constructor, after the `CoreEncryptionService` (`service`) is partially created:
      - Create the scope-specific `dekService` instance using `dek.NewService`.
      - **Dependencies for `dek.NewService`:**
        - `config`: Fetch the initial configuration for the scope this `CoreEncryptionService` represents (system or organization default) using the injected `configManager`. Handle potential errors if the initial config cannot be fetched.
        - `kmsGetter`: Pass the `CoreEncryptionService` instance itself (`service`) because it will implement the `KMSServiceGetter` interface (see next step).
        - `auditLogger`: Pass the injected `auditLogger`.
        - `store`: Create a new `store.NewMongoDBStore(db)`.
        - `cacheStore`: Create `encCacheAdapter.NewGarnetDEKCacheAdapter(appCache)` if `appCache` is not nil and cache is enabled in the fetched `config`.
        - `encryptionKey`: Pass the `systemKey`.
        - `opLogger`: Pass `log.Logger` (or a more specific logger if available).
      - Store the created `dekService` in the `service.dekService` field.
      - Immediately call `service.dekService.Initialize(context.Background())`. Log any non-critical initialization errors (like DEK not found) but potentially return critical errors (like failure to connect to KMS based on initial config).

3.  **Implement `KMSServiceGetter` on `CoreEncryptionService` (`internal/encryption/settings/core_service.go`):**

    - Add the method: `func (s *CoreEncryptionService) GetKMSProvider(ctx context.Context, scope string, scopeID string) (encInterfaces.KMSProvider, error)`.
    - This method will contain the logic previously in `getScopedServices` to:
      - Check the `s.kmsProviderCache` using `s.kmsCacheMutex`.
      - If not found, fetch the config for the _requested_ `scope`/`scopeID` using `s.configManager`.
      - Initialize the KMS provider using `utils.InitializeKMSProvider` with the fetched config and `s.systemKey`.
      - Store the initialized provider in `s.kmsProviderCache`.
      - Return the provider.

4.  **Remove `getScopedServices` (`internal/encryption/settings/core_service.go`):**

    - Delete the entire `getScopedServices` function.

5.  **Update Methods in `CoreEncryptionService` (`internal/encryption/settings/core_service.go`):**

    - Modify methods like `EnableEncryption`, `DisableEncryption`, `GetDEKStatus`, `CreateDEK`, `DeleteDEK`, `RotateDEK`, `GetDEK`, `GetFieldService`, `GetDEKService` that previously called `getScopedServices`.
    - These methods should now directly use the instance field `s.dekService`.
    - Methods needing a `FieldService` should create it on demand: `fieldService := field.NewFieldService(s.dekService, s.auditLogger, scope, scopeID)`.

6.  **Remove Old `GetKMSProvider` (`internal/encryption/settings/core_service.go`):**

    - Delete the existing `GetKMSProvider` method. The implementation added in Step 3 replaces it and serves the `KMSServiceGetter` interface for the internal `dekService`.

7.  **Update `InvalidateCacheForScope` (`internal/encryption/settings/core_service.go`):**

    - Keep the existing logic to invalidate the KMS provider cache (`s.kmsProviderCache`).
    - Add a call to `s.dekService.InvalidateCache(scope, scopeID)` to clear the DEK service's internal caches (DEK info, unwrapped DEK).
    - **Note:** This requires adding an `InvalidateCache(scope, scopeID string)` method to the `encInterfaces.DEKService` interface and its implementation in `dek/service.go`.

8.  **Modify `dek/service.go` (Related Change):**
    - Add the `InvalidateCache(scope, scopeID string)` method to the `dekService` struct and the `encInterfaces.DEKService` interface. This method should delete relevant keys (e.g., `dek_info:<scope>:<scopeID>`, `dek:<scope>:<scopeID>:<dekId>:*`) from its internal `s.cache`.

## Benefits

- **True Scope Isolation:** Each `CoreEncryptionService` (system and organization) manages a `dekService` configured only for its specific scope.
- **Removes Global State:** Eliminates reliance on the problematic global `dekService` singleton.
- **Improved Testability:** Services can be instantiated and tested independently.
- **Clearer Dependencies:** Dependencies are explicitly injected and managed within the relevant service scope.
- **Maintains Performance:** Leverages existing KMS provider caching within `CoreEncryptionService` and DEK caching within `dekService`.

## Implementation Order

1.  Modify `dek/service.go` (Remove singleton, add `InvalidateCache`).
2.  Modify `encInterfaces.DEKService` (Add `InvalidateCache`).
3.  Modify `CoreEncryptionService` struct and `NewCoreEncryptionService`.
4.  Implement `KMSServiceGetter` on `CoreEncryptionService`.
5.  Remove `getScopedServices` and old `GetKMSProvider`.
6.  Update methods in `CoreEncryptionService` to use `s.dekService`.
7.  Update `InvalidateCacheForScope`.
8.  Modify `server.go` (Remove `InitializeGlobalService` call).
9.  Refactor `EncryptionFactory` (Remove delegated methods).
10. Verify handlers use correct services.
