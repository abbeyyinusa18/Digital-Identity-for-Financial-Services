;; consent-tracking.clar
;; Records user permissions for data sharing

(define-data-var admin principal tx-sender)

;; Define consent types
(define-constant CONSENT_TYPE_BASIC_INFO 1)
(define-constant CONSENT_TYPE_FINANCIAL 2)
(define-constant CONSENT_TYPE_MARKETING 3)
(define-constant CONSENT_TYPE_THIRD_PARTY 4)
(define-constant CONSENT_TYPE_CUSTOM 5)

;; Map to store consent records
(define-map consent-records
  { user: principal, data-requester: principal, consent-type: uint }
  {
    granted: bool,
    granted-at: uint,
    expires-at: (optional uint),
    revoked-at: (optional uint),
    purpose: (string-utf8 256)
  }
)

;; Map to store consent audit logs
(define-map consent-audit-logs
  { user: principal, data-requester: principal, consent-type: uint, log-id: uint }
  { action: (string-ascii 10), timestamp: uint, actor: principal }
)

;; Map to track audit log counts
(define-map audit-log-counts
  { user: principal, data-requester: principal, consent-type: uint }
  { count: uint }
)

;; Error codes
(define-constant ERR_UNAUTHORIZED 1)
(define-constant ERR_INVALID_EXPIRY 2)
(define-constant ERR_ALREADY_GRANTED 3)
(define-constant ERR_ALREADY_REVOKED 4)
(define-constant ERR_NOT_GRANTED 5)

;; Check if caller is admin
(define-private (is-admin)
  (is-eq tx-sender (var-get admin))
)

;; Add audit log entry
(define-private (add-audit-log (user principal) (data-requester principal) (consent-type uint) (action (string-ascii 10)))
  (let ((log-count-data (default-to
                          { count: u0 }
                          (map-get? audit-log-counts { user: user, data-requester: data-requester, consent-type: consent-type })))
        (new-log-id (+ (get count log-count-data) u1)))

    ;; Add log entry
    (map-set consent-audit-logs
      { user: user, data-requester: data-requester, consent-type: consent-type, log-id: new-log-id }
      {
        action: action,
        timestamp: block-height,
        actor: tx-sender
      }
    )

    ;; Update log count
    (map-set audit-log-counts
      { user: user, data-requester: data-requester, consent-type: consent-type }
      { count: new-log-id }
    )

    new-log-id
  )
)

;; Grant consent
(define-public (grant-consent
  (data-requester principal)
  (consent-type uint)
  (purpose (string-utf8 256))
  (expires-at (optional uint)))

  (let ((current-consent (map-get? consent-records
                          { user: tx-sender, data-requester: data-requester, consent-type: consent-type })))

    ;; Check if consent already granted
    (if (and (is-some current-consent) (get granted (unwrap-panic current-consent)))
      (err ERR_ALREADY_GRANTED)
      (begin
        ;; Validate expiry if provided
        (if (is-some expires-at)
          (asserts! (> (unwrap-panic expires-at) block-height) (err ERR_INVALID_EXPIRY))
          true
        )

        ;; Record consent
        (map-set consent-records
          { user: tx-sender, data-requester: data-requester, consent-type: consent-type }
          {
            granted: true,
            granted-at: block-height,
            expires-at: expires-at,
            revoked-at: none,
            purpose: purpose
          }
        )

        ;; Add audit log
        (add-audit-log tx-sender data-requester consent-type "GRANTED")

        (ok true)
      )
    )
  )
)

;; Revoke consent
(define-public (revoke-consent (data-requester principal) (consent-type uint))
  (let ((current-consent (map-get? consent-records
                          { user: tx-sender, data-requester: data-requester, consent-type: consent-type })))

    ;; Check consent exists and is granted
    (asserts! (is-some current-consent) (err ERR_NOT_GRANTED))
    (let ((unwrapped-consent (unwrap-panic current-consent)))
      (asserts! (get granted unwrapped-consent) (err ERR_NOT_GRANTED))
      (asserts! (is-none (get revoked-at unwrapped-consent)) (err ERR_ALREADY_REVOKED))

      ;; Update consent record
      (map-set consent-records
        { user: tx-sender, data-requester: data-requester, consent-type: consent-type }
        (merge unwrapped-consent { granted: false, revoked-at: (some block-height) })
      )

      ;; Add audit log
      (add-audit-log tx-sender data-requester consent-type "REVOKED")

      (ok true)
    )
  )
)

;; Check if consent is granted
(define-read-only (check-consent (user principal) (data-requester principal) (consent-type uint))
  (let ((consent (map-get? consent-records { user: user, data-requester: data-requester, consent-type: consent-type })))
    (if (is-some consent)
      (let ((unwrapped-consent (unwrap-panic consent)))
        (and
          (get granted unwrapped-consent)
          (is-none (get revoked-at unwrapped-consent))
          (match (get expires-at unwrapped-consent)
            expiry (> expiry block-height)
            true
          )
        ))
      false
    )
  )
)

;; Get consent record
(define-read-only (get-consent-record (user principal) (data-requester principal) (consent-type uint))
  (map-get? consent-records { user: user, data-requester: data-requester, consent-type: consent-type })
)

;; Get audit log entry
(define-read-only (get-audit-log-entry (user principal) (data-requester principal) (consent-type uint) (log-id uint))
  (map-get? consent-audit-logs { user: user, data-requester: data-requester, consent-type: consent-type, log-id: log-id })
)

;; Get audit log count
(define-read-only (get-audit-log-count (user principal) (data-requester principal) (consent-type uint))
  (default-to u0 (get count (map-get? audit-log-counts { user: user, data-requester: data-requester, consent-type: consent-type })))
)

;; Transfer admin role
(define-public (transfer-admin (new-admin principal))
  (begin
    (asserts! (is-admin) (err ERR_UNAUTHORIZED))
    (var-set admin new-admin)
    (ok true)
  )
)

