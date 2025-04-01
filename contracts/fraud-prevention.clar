;; fraud-prevention.clar
;; Identifies suspicious patterns and activities

(define-data-var admin principal tx-sender)

;; Define risk levels
(define-constant RISK_LEVEL_LOW 1)
(define-constant RISK_LEVEL_MEDIUM 2)
(define-constant RISK_LEVEL_HIGH 3)

;; Define activity types
(define-constant ACTIVITY_TYPE_LOGIN 1)
(define-constant ACTIVITY_TYPE_TRANSACTION 2)
(define-constant ACTIVITY_TYPE_PROFILE_UPDATE 3)
(define-constant ACTIVITY_TYPE_CREDENTIAL_USE 4)

;; Map to store user risk scores
(define-map user-risk-scores
  { user: principal }
  {
    score: uint,
    last-updated: uint,
    flagged: bool
  }
)

;; Map to store activity logs
(define-map activity-logs
  { user: principal, activity-id: uint }
  {
    activity-type: uint,
    timestamp: uint,
    risk-score: uint,
    metadata: (string-utf8 256),
    ip-hash: (buff 32)
  }
)

;; Map to track activity counts
(define-map activity-counts
  { user: principal }
  { count: uint }
)

;; Map to store risk thresholds
(define-map risk-thresholds
  { activity-type: uint }
  {
    medium-threshold: uint,
    high-threshold: uint
  }
)

;; Map to store fraud analysts
(define-map fraud-analysts
  { analyst: principal }
  { active: bool }
)

;; Error codes
(define-constant ERR_UNAUTHORIZED 1)
(define-constant ERR_INVALID_RISK_LEVEL 2)
(define-constant ERR_INVALID_ACTIVITY_TYPE 3)
(define-constant ERR_USER_NOT_FOUND 4)

;; Check if caller is admin
(define-private (is-admin)
  (is-eq tx-sender (var-get admin))
)

;; Check if caller is a fraud analyst
(define-private (is-fraud-analyst)
  (default-to false (get active (map-get? fraud-analysts { analyst: tx-sender })))
)

;; Add a fraud analyst
(define-public (add-fraud-analyst (analyst principal))
  (begin
    (asserts! (is-admin) (err ERR_UNAUTHORIZED))
    (ok (map-set fraud-analysts { analyst: analyst } { active: true }))
  )
)

;; Remove a fraud analyst
(define-public (remove-fraud-analyst (analyst principal))
  (begin
    (asserts! (is-admin) (err ERR_UNAUTHORIZED))
    (ok (map-set fraud-analysts { analyst: analyst } { active: false }))
  )
)

;; Set risk threshold for activity type
(define-public (set-risk-threshold (activity-type uint) (medium-threshold uint) (high-threshold uint))
  (begin
    (asserts! (is-admin) (err ERR_UNAUTHORIZED))
    (asserts! (< medium-threshold high-threshold) (err ERR_INVALID_RISK_LEVEL))
    (ok (map-set risk-thresholds
      { activity-type: activity-type }
      {
        medium-threshold: medium-threshold,
        high-threshold: high-threshold
      }))
  )
)

;; Calculate risk level based on score and thresholds
(define-private (calculate-risk-level (score uint) (activity-type uint))
  (let ((thresholds (default-to
                      { medium-threshold: u50, high-threshold: u75 }
                      (map-get? risk-thresholds { activity-type: activity-type }))))
    (if (>= score (get high-threshold thresholds))
      RISK_LEVEL_HIGH
      (if (>= score (get medium-threshold thresholds))
        RISK_LEVEL_MEDIUM
        RISK_LEVEL_LOW
      )
    )
  )
)

;; Log activity and update risk score
(define-public (log-activity
  (user principal)
  (activity-type uint)
  (risk-score uint)
  (metadata (string-utf8 256))
  (ip-hash (buff 32)))

  (begin
    ;; Only admin, fraud analyst, or the user themselves can log activity
    (asserts! (or (is-admin) (is-fraud-analyst) (is-eq tx-sender user)) (err ERR_UNAUTHORIZED))

    (let ((activity-count-data (default-to { count: u0 } (map-get? activity-counts { user: user })))
          (new-activity-id (+ (get count activity-count-data) u1))
          (current-risk-data (default-to
                              { score: u0, last-updated: u0, flagged: false }
                              (map-get? user-risk-scores { user: user }))))

      ;; Log the activity
      (map-set activity-logs
        { user: user, activity-id: new-activity-id }
        {
          activity-type: activity-type,
          timestamp: block-height,
          risk-score: risk-score,
          metadata: metadata,
          ip-hash: ip-hash
        }
      )

      ;; Update activity count
      (map-set activity-counts
        { user: user }
        { count: new-activity-id }
      )

      ;; Update user risk score (simple average for demonstration)
      (let ((new-score (/ (+ (get score current-risk-data) risk-score) u2))
            (risk-level (calculate-risk-level new-score activity-type)))

        (map-set user-risk-scores
          { user: user }
          {
            score: new-score,
            last-updated: block-height,
            flagged: (is-eq risk-level RISK_LEVEL_HIGH)
          }
        )

        (ok { activity-id: new-activity-id, risk-level: risk-level })
      )
    )
  )
)

;; Manually flag a user
(define-public (flag-user (user principal))
  (begin
    (asserts! (or (is-admin) (is-fraud-analyst)) (err ERR_UNAUTHORIZED))

    (let ((current-risk-data (map-get? user-risk-scores { user: user })))
      (asserts! (is-some current-risk-data) (err ERR_USER_NOT_FOUND))

      (map-set user-risk-scores
        { user: user }
        (merge (unwrap-panic current-risk-data) { flagged: true })
      )

      (ok true)
    )
  )
)

;; Clear flag from a user
(define-public (clear-user-flag (user principal))
  (begin
    (asserts! (or (is-admin) (is-fraud-analyst)) (err ERR_UNAUTHORIZED))

    (let ((current-risk-data (map-get? user-risk-scores { user: user })))
      (asserts! (is-some current-risk-data) (err ERR_USER_NOT_FOUND))

      (map-set user-risk-scores
        { user: user }
        (merge (unwrap-panic current-risk-data) { flagged: false })
      )

      (ok true)
    )
  )
)

;; Get user risk score
(define-read-only (get-user-risk-score (user principal))
  (map-get? user-risk-scores { user: user })
)

;; Get activity log
(define-read-only (get-activity-log (user principal) (activity-id uint))
  (map-get? activity-logs { user: user, activity-id: activity-id })
)

;; Get activity count
(define-read-only (get-activity-count (user principal))
  (default-to u0 (get count (map-get? activity-counts { user: user })))
)

;; Check if user is flagged
(define-read-only (is-user-flagged (user principal))
  (default-to false (get flagged (map-get? user-risk-scores { user: user })))
)

;; Transfer admin role
(define-public (transfer-admin (new-admin principal))
  (begin
    (asserts! (is-admin) (err ERR_UNAUTHORIZED))
    (var-set admin new-admin)
    (ok true)
  )
)

