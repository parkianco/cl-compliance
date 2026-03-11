;;;; cl-compliance - Verification Management
;;;; KYC status tracking and verification requests

(in-package #:cl-compliance)

;;; ============================================================================
;;; KYC States
;;; ============================================================================

(defconstant +kyc-state-not-started+ :not-started)
(defconstant +kyc-state-in-progress+ :in-progress)
(defconstant +kyc-state-pending-review+ :pending-review)
(defconstant +kyc-state-approved+ :approved)
(defconstant +kyc-state-rejected+ :rejected)
(defconstant +kyc-state-expired+ :expired)
(defconstant +kyc-state-suspended+ :suspended)

;;; ============================================================================
;;; Valid State Transitions
;;; ============================================================================

(defparameter *valid-transitions*
  '((:not-started . (:in-progress))
    (:in-progress . (:pending-review :rejected))
    (:pending-review . (:approved :rejected :in-progress))
    (:approved . (:expired :suspended))
    (:rejected . (:in-progress))
    (:expired . (:in-progress))
    (:suspended . (:in-progress :approved)))
  "Valid KYC state transitions.")

;;; ============================================================================
;;; Verification Structures
;;; ============================================================================

(defstruct verification-request
  "A verification request for an identity."
  (id "" :type string)
  (identity-id "" :type string)
  (type :document :type keyword)
  (status :pending :type keyword)
  (created-at 0 :type integer)
  (completed-at 0 :type integer)
  (result nil)
  (metadata (make-hash-table :test 'equal) :type hash-table))

(defstruct kyc-status
  "KYC status for an identity."
  (identity-id "" :type string)
  (level 0 :type integer)
  (state :not-started :type keyword)
  (checks-completed '() :type list)
  (checks-pending '() :type list)
  (checks-failed '() :type list)
  (last-updated 0 :type integer)
  (next-review 0 :type integer)
  (notes "" :type string))

;;; ============================================================================
;;; KYC Status Manager
;;; ============================================================================

(defparameter *kyc-status-store* (make-hash-table :test 'equal)
  "Storage for KYC status records.")

(defparameter *verification-request-store* (make-hash-table :test 'equal)
  "Storage for verification requests.")

(defun get-kyc-status (identity-id)
  "Get KYC status for an identity."
  (or (gethash identity-id *kyc-status-store*)
      (let ((status (make-kyc-status
                     :identity-id identity-id
                     :state :not-started
                     :last-updated (get-universal-time))))
        (setf (gethash identity-id *kyc-status-store*) status)
        status)))

(defun update-kyc-status (identity-id &key level state checks-completed checks-pending notes)
  "Update KYC status for an identity."
  (let ((status (get-kyc-status identity-id)))
    (when level
      (setf (kyc-status-level status) level))
    (when state
      (setf (kyc-status-state status) state))
    (when checks-completed
      (setf (kyc-status-checks-completed status) checks-completed))
    (when checks-pending
      (setf (kyc-status-checks-pending status) checks-pending))
    (when notes
      (setf (kyc-status-notes status) notes))
    (setf (kyc-status-last-updated status) (get-universal-time))
    status))

;;; ============================================================================
;;; State Transitions
;;; ============================================================================

(defun valid-status-transition-p (current-state new-state)
  "Check if a state transition is valid."
  (let ((allowed (cdr (assoc current-state *valid-transitions*))))
    (member new-state allowed)))

(defun transition-kyc-status (identity-id new-state &key reason)
  "Transition KYC status to a new state."
  (let* ((status (get-kyc-status identity-id))
         (current-state (kyc-status-state status)))
    (unless (valid-status-transition-p current-state new-state)
      (error 'compliance-error
             :code :invalid-transition
             :message (format nil "Cannot transition from ~A to ~A"
                              current-state new-state)))
    (setf (kyc-status-state status) new-state
          (kyc-status-last-updated status) (get-universal-time))
    (when reason
      (setf (kyc-status-notes status) reason))
    status))

;;; ============================================================================
;;; Verification Requests
;;; ============================================================================

(defun submit-verification-request (identity-id type &key metadata)
  "Submit a new verification request."
  (let ((request (make-verification-request
                  :id (generate-uuid)
                  :identity-id identity-id
                  :type type
                  :status :pending
                  :created-at (get-universal-time)
                  :metadata (or metadata (make-hash-table :test 'equal)))))
    (setf (gethash (verification-request-id request) *verification-request-store*) request)
    ;; Update KYC status
    (let ((status (get-kyc-status identity-id)))
      (pushnew type (kyc-status-checks-pending status))
      (when (eq (kyc-status-state status) :not-started)
        (transition-kyc-status identity-id :in-progress)))
    request))

(defun process-verification-request (request-id result)
  "Process a verification request with result."
  (let ((request (gethash request-id *verification-request-store*)))
    (unless request
      (error 'compliance-error
             :code :request-not-found
             :message "Verification request not found"))
    (setf (verification-request-status request)
          (if (getf result :success) :completed :failed)
          (verification-request-completed-at request) (get-universal-time)
          (verification-request-result request) result)
    ;; Update KYC status
    (let* ((identity-id (verification-request-identity-id request))
           (status (get-kyc-status identity-id))
           (type (verification-request-type request)))
      (setf (kyc-status-checks-pending status)
            (remove type (kyc-status-checks-pending status)))
      (if (getf result :success)
          (pushnew type (kyc-status-checks-completed status))
          (pushnew type (kyc-status-checks-failed status)))
      ;; Check if all checks complete
      (when (null (kyc-status-checks-pending status))
        (if (null (kyc-status-checks-failed status))
            (transition-kyc-status identity-id :pending-review)
            (transition-kyc-status identity-id :rejected
                                   :reason "One or more verification checks failed"))))
    request))

(defun get-verification-request-status (request-id)
  "Get status of a verification request."
  (let ((request (gethash request-id *verification-request-store*)))
    (when request
      (verification-request-status request))))
