;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause

;;;; cl-compliance - Error Conditions
;;;; Condition types for compliance operations

(in-package #:cl-compliance)

;;; ============================================================================
;;; Base Condition
;;; ============================================================================

(define-condition compliance-error (error)
  ((code :initarg :code :reader compliance-error-code :initform :unknown)
   (message :initarg :message :reader compliance-error-message :initform "")
   (details :initarg :details :reader compliance-error-details :initform nil))
  (:report (lambda (condition stream)
             (format stream "Compliance Error [~A]: ~A"
                     (compliance-error-code condition)
                     (compliance-error-message condition)))))

;;; ============================================================================
;;; Specific Conditions
;;; ============================================================================

(define-condition identity-not-found-error (compliance-error)
  ((identity-id :initarg :identity-id :reader identity-not-found-identity-id))
  (:default-initargs :code :identity-not-found :message "Identity not found"))

(define-condition verification-failed-error (compliance-error)
  ((verification-type :initarg :verification-type :reader verification-failed-type)
   (reason :initarg :reason :reader verification-failed-reason))
  (:default-initargs :code :verification-failed :message "Verification failed"))

(define-condition document-expired-error (compliance-error)
  ((document-id :initarg :document-id :reader document-expired-document-id)
   (expiry-date :initarg :expiry-date :reader document-expired-date))
  (:default-initargs :code :document-expired :message "Document has expired"))

(define-condition sanctions-match-error (compliance-error)
  ((match-details :initarg :match-details :reader sanctions-match-details))
  (:default-initargs :code :sanctions-match :message "Sanctions list match detected"))

(define-condition compliance-violation-error (compliance-error)
  ((rule-id :initarg :rule-id :reader compliance-violation-rule-id)
   (violation-details :initarg :violation-details :reader compliance-violation-details))
  (:default-initargs :code :compliance-violation :message "Compliance rule violation"))
