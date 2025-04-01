;; identity-verification.clar
;; Validates user information through trusted sources

(define-data-var admin principal tx-sender)

;; Define verification status enum
(define-constant STATUS_UNVERIFIED u0)
(define-constant STATUS_PENDING u1)
(define-constant STATUS_VERIFIED u2)
(define-constant STATUS_REJECTED u3)

;; Map to store verification status for each user
(define-map verification-status
  { user: principal }
  { status: uint, timestamp: uint, verifier: (optional principal) }
)

;; Map to store user information
(define-map user-info
  { user: principal }
  {
    name: (string-utf8 100),
    document-hash: (buff 32),
    metadata: (string-utf8 256)
  }
)

;; Map to store trusted verifiers
(define-map trusted-verifiers
  { verifier: principal }
  { active: bool }
)

;; Error codes
(define-constant ERR_UNAUTHORIZED u1)
(define-constant ERR_ALREADY_VERIFIED u2)
(define-constant ERR_INVALID_STATUS u3)
(define-constant ERR_USER_NOT_FOUND u4)

;; Check if caller is admin
(define-private (is-admin)
  (is-eq tx-sender (var-get admin))
)

;; Check if caller is a trusted verifier
(define-private (is-trusted-verifier)
  (default-to false (get active (map-get? trusted-verifiers { verifier: tx-sender })))
)

;; Add a trusted verifier
(define-public (add-trusted-verifier (verifier principal))
  (begin
    (asserts! (is-admin) (err ERR_UNAUTHORIZED))
    (ok (map-set trusted-verifiers { verifier: verifier } { active: true }))
  )
)

;; Remove a trusted verifier
(define-public (remove-trusted-verifier (verifier principal))
  (begin
    (asserts! (is-admin) (err ERR_UNAUTHORIZED))
    (ok (map-set trusted-verifiers { verifier: verifier } { active: false }))
  )
)

;; Submit user information for verification
(define-public (submit-for-verification (name (string-utf8 100)) (document-hash (buff 32)) (metadata (string-utf8 256)))
  (begin
    ;; Store user information
    (map-set user-info
      { user: tx-sender }
      {
        name: name,
        document-hash: document-hash,
        metadata: metadata
      }
    )

    ;; Set status to pending
    (map-set verification-status
      { user: tx-sender }
      {
        status: STATUS_PENDING,
        timestamp: block-height,
        verifier: none
      }
    )

    (ok true)
  )
)

;; Verify a user
(define-public (verify-user (user principal))
  (begin
    (asserts! (is-trusted-verifier) (err ERR_UNAUTHORIZED))

    (let ((current-status (default-to
                            { status: STATUS_UNVERIFIED, timestamp: u0, verifier: none }
                            (map-get? verification-status { user: user }))))

      (asserts! (is-eq (get status current-status) STATUS_PENDING) (err ERR_INVALID_STATUS))

      (map-set verification-status
        { user: user }
        {
          status: STATUS_VERIFIED,
          timestamp: block-height,
          verifier: (some tx-sender)
        }
      )

      (ok true)
    )
  )
)

;; Reject a user verification
(define-public (reject-verification (user principal))
  (begin
    (asserts! (is-trusted-verifier) (err ERR_UNAUTHORIZED))

    (let ((current-status (default-to
                            { status: STATUS_UNVERIFIED, timestamp: u0, verifier: none }
                            (map-get? verification-status { user: user }))))

      (asserts! (is-eq (get status current-status) STATUS_PENDING) (err ERR_INVALID_STATUS))

      (map-set verification-status
        { user: user }
        {
          status: STATUS_REJECTED,
          timestamp: block-height,
          verifier: (some tx-sender)
        }
      )

      (ok true)
    )
  )
)

;; Get verification status
(define-read-only (get-verification-status (user principal))
  (default-to
    { status: STATUS_UNVERIFIED, timestamp: u0, verifier: none }
    (map-get? verification-status { user: user })
  )
)

;; Get user information
(define-read-only (get-user-info (user principal))
  (map-get? user-info { user: user })
)

;; Check if user is verified
(define-read-only (is-verified (user principal))
  (is-eq (get status (get-verification-status user)) STATUS_VERIFIED)
)

;; Transfer admin role
(define-public (transfer-admin (new-admin principal))
  (begin
    (asserts! (is-admin) (err ERR_UNAUTHORIZED))
    (var-set admin new-admin)
    (ok true)
  )
)

