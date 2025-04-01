;; credential-management.clar
;; Issues verifiable claims about users

(define-data-var admin principal tx-sender)

;; Define credential types
(define-constant CREDENTIAL_TYPE_KYC 1)
(define-constant CREDENTIAL_TYPE_ACCREDITED 2)
(define-constant CREDENTIAL_TYPE_FINANCIAL 3)
(define-constant CREDENTIAL_TYPE_CUSTOM 4)

;; Map to store credentials
(define-map credentials
  { user: principal, credential-id: uint }
  {
    credential-type: uint,
    issuer: principal,
    issued-at: uint,
    expires-at: uint,
    revoked: bool,
    data-hash: (buff 32)
  }
)

;; Map to store credential issuers
(define-map credential-issuers
  { issuer: principal, credential-type: uint }
  { authorized: bool }
)

;; Map to track user's credentials
(define-map user-credentials
  { user: principal }
  { credential-count: uint }
)

;; Error codes
(define-constant ERR_UNAUTHORIZED 1)
(define-constant ERR_INVALID_EXPIRY 2)
(define-constant ERR_CREDENTIAL_NOT_FOUND 3)
(define-constant ERR_ALREADY_REVOKED 4)
(define-constant ERR_EXPIRED 5)

;; Check if caller is admin
(define-private (is-admin)
  (is-eq tx-sender (var-get admin))
)

;; Check if caller is authorized issuer for credential type
(define-private (is-authorized-issuer (credential-type uint))
  (default-to
    false
    (get authorized (map-get? credential-issuers { issuer: tx-sender, credential-type: credential-type }))
  )
)

;; Authorize an issuer for a credential type
(define-public (authorize-issuer (issuer principal) (credential-type uint))
  (begin
    (asserts! (is-admin) (err ERR_UNAUTHORIZED))
    (ok (map-set credential-issuers
      { issuer: issuer, credential-type: credential-type }
      { authorized: true }))
  )
)

;; Revoke issuer authorization
(define-public (revoke-issuer-authorization (issuer principal) (credential-type uint))
  (begin
    (asserts! (is-admin) (err ERR_UNAUTHORIZED))
    (ok (map-set credential-issuers
      { issuer: issuer, credential-type: credential-type }
      { authorized: false }))
  )
)

;; Issue a credential
(define-public (issue-credential
  (user principal)
  (credential-type uint)
  (expires-at uint)
  (data-hash (buff 32)))

  (let ((user-cred-data (default-to { credential-count: u0 } (map-get? user-credentials { user: user })))
        (new-credential-id (+ (get credential-count user-cred-data) u1)))

    ;; Check authorization
    (asserts! (is-authorized-issuer credential-type) (err ERR_UNAUTHORIZED))

    ;; Check expiry is in future
    (asserts! (> expires-at block-height) (err ERR_INVALID_EXPIRY))

    ;; Store credential
    (map-set credentials
      { user: user, credential-id: new-credential-id }
      {
        credential-type: credential-type,
        issuer: tx-sender,
        issued-at: block-height,
        expires-at: expires-at,
        revoked: false,
        data-hash: data-hash
      }
    )

    ;; Update user credential count
    (map-set user-credentials
      { user: user }
      { credential-count: new-credential-id }
    )

    (ok new-credential-id)
  )
)

;; Revoke a credential
(define-public (revoke-credential (user principal) (credential-id uint))
  (let ((credential (map-get? credentials { user: user, credential-id: credential-id })))

    ;; Check credential exists
    (asserts! (is-some credential) (err ERR_CREDENTIAL_NOT_FOUND))

    (let ((unwrapped-credential (unwrap-panic credential)))
      ;; Check authorization (only issuer or admin can revoke)
      (asserts! (or
                  (is-eq tx-sender (get issuer unwrapped-credential))
                  (is-admin))
                (err ERR_UNAUTHORIZED))

      ;; Check not already revoked
      (asserts! (not (get revoked unwrapped-credential)) (err ERR_ALREADY_REVOKED))

      ;; Update credential to revoked
      (map-set credentials
        { user: user, credential-id: credential-id }
        (merge unwrapped-credential { revoked: true })
      )

      (ok true)
    )
  )
)

;; Get credential
(define-read-only (get-credential (user principal) (credential-id uint))
  (map-get? credentials { user: user, credential-id: credential-id })
)

;; Verify credential is valid (not expired, not revoked)
(define-read-only (verify-credential (user principal) (credential-id uint))
  (let ((credential (map-get? credentials { user: user, credential-id: credential-id })))
    (if (is-some credential)
      (let ((unwrapped-credential (unwrap-panic credential)))
        (and
          (not (get revoked unwrapped-credential))
          (> (get expires-at unwrapped-credential) block-height)
        ))
      false
    )
  )
)

;; Get user credential count
(define-read-only (get-user-credential-count (user principal))
  (default-to u0 (get credential-count (map-get? user-credentials { user: user })))
)

;; Transfer admin role
(define-public (transfer-admin (new-admin principal))
  (begin
    (asserts! (is-admin) (err ERR_UNAUTHORIZED))
    (var-set admin new-admin)
    (ok true)
  )
)

