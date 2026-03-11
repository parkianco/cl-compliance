;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause

;;;; cl-compliance - Identity Management
;;;; Identity records, attributes, and verification levels

(in-package #:cl-compliance)

;;; ============================================================================
;;; Identity Types
;;; ============================================================================

(defconstant +identity-type-individual+ :individual
  "Identity type for natural persons.")

(defconstant +identity-type-business+ :business
  "Identity type for business entities.")

(defconstant +identity-type-trust+ :trust
  "Identity type for trusts.")

(defconstant +identity-type-foundation+ :foundation
  "Identity type for foundations.")

;;; ============================================================================
;;; Verification Levels
;;; ============================================================================

(defconstant +verification-level-none+ 0
  "No verification performed.")

(defconstant +verification-level-basic+ 1
  "Basic verification (email, phone).")

(defconstant +verification-level-standard+ 2
  "Standard verification (ID document).")

(defconstant +verification-level-enhanced+ 3
  "Enhanced verification (multiple documents, liveness).")

(defconstant +verification-level-premium+ 4
  "Premium verification (full due diligence).")

;;; ============================================================================
;;; Identity Structures
;;; ============================================================================

(defstruct identity-attribute
  "A verified attribute of an identity."
  (name "" :type string)
  (value nil)
  (verified nil :type boolean)
  (source "" :type string)
  (confidence 0.0 :type float)
  (timestamp 0 :type integer))

(defstruct identity-record
  "An identity record for KYC purposes."
  (id "" :type string)
  (type :individual :type keyword)
  (attributes '() :type list)
  (verified-at 0 :type integer)
  (expires-at 0 :type integer)
  (status :pending :type keyword)
  (risk-score 0.0 :type float)
  (metadata (make-hash-table :test 'equal) :type hash-table)
  (created-at 0 :type integer)
  (updated-at 0 :type integer))

;;; ============================================================================
;;; Identity Manager
;;; ============================================================================

(defstruct identity-manager
  "Manager for identity records."
  (store (make-hash-table :test 'equal) :type hash-table)
  (config (make-hash-table :test 'equal) :type hash-table)
  (wallet-links (make-hash-table :test 'equal) :type hash-table))

;;; ============================================================================
;;; Identity Operations
;;; ============================================================================

(defun create-identity (manager type &key attributes)
  "Create a new identity record."
  (let* ((id (generate-uuid))
         (now (get-universal-time))
         (identity (make-identity-record
                    :id id
                    :type type
                    :attributes (or attributes '())
                    :status :pending
                    :risk-score 0.0
                    :created-at now
                    :updated-at now)))
    (setf (gethash id (identity-manager-store manager)) identity)
    identity))

(defun get-identity (manager identity-id)
  "Get identity record by ID."
  (or (gethash identity-id (identity-manager-store manager))
      (error 'identity-not-found-error :identity-id identity-id)))

(defun update-identity (manager identity-id &key attributes status risk-score)
  "Update an identity record."
  (let ((identity (get-identity manager identity-id)))
    (when attributes
      (setf (identity-record-attributes identity) attributes))
    (when status
      (setf (identity-record-status identity) status))
    (when risk-score
      (setf (identity-record-risk-score identity) risk-score))
    (setf (identity-record-updated-at identity) (get-universal-time))
    identity))

(defun delete-identity (manager identity-id)
  "Delete an identity record."
  (remhash identity-id (identity-manager-store manager)))

(defun search-identities (manager &key type status min-risk max-risk)
  "Search identity records with filters."
  (let ((results '()))
    (maphash (lambda (id identity)
               (declare (ignore id))
               (when (and (or (null type) (eq (identity-record-type identity) type))
                          (or (null status) (eq (identity-record-status identity) status))
                          (or (null min-risk) (>= (identity-record-risk-score identity) min-risk))
                          (or (null max-risk) (<= (identity-record-risk-score identity) max-risk)))
                 (push identity results)))
             (identity-manager-store manager))
    results))

;;; ============================================================================
;;; Attribute Operations
;;; ============================================================================

(defun verify-identity-attribute (identity attribute-name source &key (confidence 1.0))
  "Mark an attribute as verified."
  (let ((attr (find attribute-name (identity-record-attributes identity)
                    :key #'identity-attribute-name :test #'string=)))
    (when attr
      (setf (identity-attribute-verified attr) t
            (identity-attribute-source attr) source
            (identity-attribute-confidence attr) confidence
            (identity-attribute-timestamp attr) (get-universal-time)))
    attr))

(defun get-identity-verification-level (identity)
  "Calculate verification level based on verified attributes."
  (let ((attrs (identity-record-attributes identity))
        (verified-count 0)
        (has-document nil)
        (has-liveness nil))
    (dolist (attr attrs)
      (when (identity-attribute-verified attr)
        (incf verified-count)
        (when (member (identity-attribute-name attr) '("passport" "national-id" "drivers-license")
                      :test #'string=)
          (setf has-document t))
        (when (string= (identity-attribute-name attr) "liveness")
          (setf has-liveness t))))
    (cond
      ((and has-document has-liveness (> verified-count 5)) +verification-level-premium+)
      ((and has-document has-liveness) +verification-level-enhanced+)
      (has-document +verification-level-standard+)
      ((> verified-count 0) +verification-level-basic+)
      (t +verification-level-none+))))

;;; ============================================================================
;;; Risk Scoring
;;; ============================================================================

(defun calculate-identity-risk-score (identity)
  "Calculate risk score for an identity (0.0 = low risk, 1.0 = high risk)."
  (let ((score 0.0)
        (factors 0))
    ;; Check verification status
    (when (eq (identity-record-status identity) :pending)
      (incf score 0.3)
      (incf factors))

    ;; Check expiry
    (let ((expires (identity-record-expires-at identity)))
      (when (and (> expires 0)
                 (< expires (get-universal-time)))
        (incf score 0.4)
        (incf factors)))

    ;; Check for high-risk country
    (dolist (attr (identity-record-attributes identity))
      (when (and (string= (identity-attribute-name attr) "country")
                 (is-high-risk-country-p (identity-attribute-value attr)))
        (incf score 0.3)
        (incf factors)))

    ;; Normalize
    (setf (identity-record-risk-score identity)
          (if (> factors 0) (/ score factors) 0.0))
    (identity-record-risk-score identity)))

;;; ============================================================================
;;; Wallet Linking
;;; ============================================================================

(defun link-wallet-to-identity (manager identity-id wallet-address)
  "Link a wallet address to an identity."
  (let ((links (identity-manager-wallet-links manager)))
    (push identity-id (gethash wallet-address links))
    (setf (gethash wallet-address links)
          (remove-duplicates (gethash wallet-address links) :test #'string=))))

(defun unlink-wallet-from-identity (manager identity-id wallet-address)
  "Unlink a wallet address from an identity."
  (let ((links (identity-manager-wallet-links manager)))
    (setf (gethash wallet-address links)
          (remove identity-id (gethash wallet-address links) :test #'string=))))

(defun get-identity-for-wallet (manager wallet-address)
  "Get identity linked to a wallet address."
  (let ((identity-ids (gethash wallet-address (identity-manager-wallet-links manager))))
    (when identity-ids
      (get-identity manager (first identity-ids)))))

(defun get-wallets-for-identity (manager identity-id)
  "Get all wallet addresses linked to an identity."
  (let ((wallets '()))
    (maphash (lambda (addr ids)
               (when (member identity-id ids :test #'string=)
                 (push addr wallets)))
             (identity-manager-wallet-links manager))
    wallets))
