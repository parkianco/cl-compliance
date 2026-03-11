;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause

;;;; cl-compliance - Document Verification
;;;; Document types, validation, and verification

(in-package #:cl-compliance)

;;; ============================================================================
;;; Document Types
;;; ============================================================================

(defconstant +document-type-passport+ :passport)
(defconstant +document-type-national-id+ :national-id)
(defconstant +document-type-drivers-license+ :drivers-license)
(defconstant +document-type-residence-permit+ :residence-permit)
(defconstant +document-type-utility-bill+ :utility-bill)
(defconstant +document-type-bank-statement+ :bank-statement)

;;; ============================================================================
;;; Document Structures
;;; ============================================================================

(defstruct verification-document
  "A document submitted for verification."
  (id "" :type string)
  (type :passport :type keyword)
  (country "" :type string)
  (number "" :type string)
  (issue-date 0 :type integer)
  (expiry-date 0 :type integer)
  (holder-name "" :type string)
  (holder-dob 0 :type integer)
  (images '() :type list)
  (hash "" :type string)
  (status :pending :type keyword)
  (created-at 0 :type integer))

(defstruct document-image
  "An image of a document."
  (id "" :type string)
  (type :front :type keyword)
  (hash "" :type string)
  (format :jpeg :type keyword)
  (size 0 :type integer)
  (encrypted-data nil))

(defstruct document-verification-result
  "Result of document verification."
  (document-id "" :type string)
  (status :pending :type keyword)
  (authenticity-score 0.0 :type float)
  (data-extraction nil)
  (fraud-signals '() :type list)
  (provider-id "" :type string)
  (timestamp 0 :type integer))

;;; ============================================================================
;;; Document Storage
;;; ============================================================================

(defparameter *document-store* (make-hash-table :test 'equal)
  "Storage for documents.")

;;; ============================================================================
;;; Document Operations
;;; ============================================================================

(defun submit-document (identity-id type country &key number issue-date expiry-date
                                                      holder-name holder-dob images)
  "Submit a document for verification."
  (let* ((id (generate-uuid))
         (document (make-verification-document
                    :id id
                    :type type
                    :country (normalize-country country)
                    :number (or number "")
                    :issue-date (or issue-date 0)
                    :expiry-date (or expiry-date 0)
                    :holder-name (or holder-name "")
                    :holder-dob (or holder-dob 0)
                    :images (or images '())
                    :status :pending
                    :created-at (get-universal-time))))
    ;; Compute document hash
    (setf (verification-document-hash document)
          (compute-document-hash document))
    ;; Store document
    (setf (gethash id *document-store*) document)
    ;; Link to identity
    (let ((identity-docs (gethash identity-id *document-store*)))
      (push id identity-docs)
      (setf (gethash identity-id *document-store*) identity-docs))
    document))

(defun verify-document (document-id)
  "Verify a document (simplified verification)."
  (let ((document (gethash document-id *document-store*)))
    (unless document
      (error 'compliance-error
             :code :document-not-found
             :message "Document not found"))
    ;; Check expiry
    (when (check-document-expiry document)
      (setf (verification-document-status document) :expired)
      (error 'document-expired-error
             :document-id document-id
             :expiry-date (verification-document-expiry-date document)))
    ;; Validate format
    (unless (validate-document-format document)
      (setf (verification-document-status document) :invalid)
      (return-from verify-document
        (make-document-verification-result
         :document-id document-id
         :status :failed
         :authenticity-score 0.0
         :timestamp (get-universal-time))))
    ;; Simplified verification - in production, this would call external providers
    (let ((result (make-document-verification-result
                   :document-id document-id
                   :status :verified
                   :authenticity-score 0.95
                   :data-extraction (extract-document-data document)
                   :timestamp (get-universal-time))))
      (setf (verification-document-status document) :verified)
      result)))

(defun extract-document-data (document)
  "Extract structured data from document."
  (list :type (verification-document-type document)
        :country (verification-document-country document)
        :number (verification-document-number document)
        :holder-name (verification-document-holder-name document)
        :holder-dob (verification-document-holder-dob document)
        :expiry-date (verification-document-expiry-date document)))

(defun validate-document-format (document)
  "Validate document format and completeness."
  (and (verification-document-type document)
       (> (length (verification-document-country document)) 0)
       (or (verification-document-images document)
           (> (length (verification-document-number document)) 0))))

(defun check-document-expiry (document)
  "Check if document has expired. Returns T if expired."
  (let ((expiry (verification-document-expiry-date document)))
    (and (> expiry 0)
         (< expiry (get-universal-time)))))

(defun compute-document-hash (document)
  "Compute hash of document for integrity verification."
  (hash-pii (format nil "~A:~A:~A:~A"
                    (verification-document-type document)
                    (verification-document-country document)
                    (verification-document-number document)
                    (verification-document-holder-name document))))
