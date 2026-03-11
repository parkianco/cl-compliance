;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause

;;;; cl-compliance - Sanctions Screening
;;;; Sanctions list management and screening

(in-package #:cl-compliance)

;;; ============================================================================
;;; Sanctions Lists
;;; ============================================================================

(defconstant +sanctions-list-ofac-sdn+ :ofac-sdn
  "OFAC Specially Designated Nationals list.")

(defconstant +sanctions-list-un-consolidated+ :un-consolidated
  "UN Consolidated Sanctions list.")

(defconstant +sanctions-list-eu-consolidated+ :eu-consolidated
  "EU Consolidated Sanctions list.")

(defconstant +sanctions-list-uk-consolidated+ :uk-consolidated
  "UK Consolidated Sanctions list.")

;;; ============================================================================
;;; Sanctions Structures
;;; ============================================================================

(defstruct sanctions-entry
  "An entry in a sanctions list."
  (id "" :type string)
  (list-id :ofac-sdn :type keyword)
  (type :individual :type keyword)
  (names '() :type list)
  (aliases '() :type list)
  (birth-dates '() :type list)
  (nationalities '() :type list)
  (addresses '() :type list)
  (identifiers '() :type list)
  (programs '() :type list)
  (remarks "" :type string)
  (added-date 0 :type integer)
  (updated-date 0 :type integer))

(defstruct screening-request
  "A request to screen an individual or entity."
  (id "" :type string)
  (identity-id "" :type string)
  (name "" :type string)
  (aliases '() :type list)
  (birth-date 0 :type integer)
  (nationality "" :type string)
  (lists '() :type list)
  (threshold 0.8 :type float)
  (created-at 0 :type integer))

(defstruct screening-result
  "Result of sanctions screening."
  (request-id "" :type string)
  (matches '() :type list)
  (timestamp 0 :type integer)
  (lists-checked '() :type list))

(defstruct screening-match
  "A potential match from screening."
  (entry-id "" :type string)
  (list-id :ofac-sdn :type keyword)
  (score 0.0 :type float)
  (matched-fields '() :type list)
  (status :pending :type keyword)
  (reviewed-by "" :type string)
  (reviewed-at 0 :type integer))

;;; ============================================================================
;;; Sanctions List Manager
;;; ============================================================================

(defparameter *sanctions-lists* (make-hash-table :test 'equal)
  "Storage for sanctions list entries.")

(defparameter *screening-results* (make-hash-table :test 'equal)
  "Storage for screening results.")

(defun load-sanctions-list (list-id entries)
  "Load sanctions list entries."
  (let ((list-store (or (gethash list-id *sanctions-lists*)
                        (make-hash-table :test 'equal))))
    (dolist (entry entries)
      (setf (gethash (sanctions-entry-id entry) list-store) entry))
    (setf (gethash list-id *sanctions-lists*) list-store)
    (hash-table-count list-store)))

(defun get-list-entry-count (list-id)
  "Get number of entries in a sanctions list."
  (let ((list-store (gethash list-id *sanctions-lists*)))
    (if list-store
        (hash-table-count list-store)
        0)))

;;; ============================================================================
;;; Screening Operations
;;; ============================================================================

(defun screen-individual (name &key aliases birth-date nationality
                                    (lists '(:ofac-sdn :un-consolidated))
                                    (threshold 0.8))
  "Screen an individual against sanctions lists."
  (let* ((request-id (generate-uuid))
         (request (make-screening-request
                   :id request-id
                   :name name
                   :aliases (or aliases '())
                   :birth-date (or birth-date 0)
                   :nationality (or nationality "")
                   :lists lists
                   :threshold threshold
                   :created-at (get-universal-time)))
         (matches '()))
    ;; Search each list
    (dolist (list-id lists)
      (let ((list-store (gethash list-id *sanctions-lists*)))
        (when list-store
          (maphash (lambda (entry-id entry)
                     (let ((match (match-against-entry request entry)))
                       (when (and match (>= (screening-match-score match) threshold))
                         (push match matches))))
                   list-store))))
    ;; Create result
    (let ((result (make-screening-result
                   :request-id request-id
                   :matches matches
                   :timestamp (get-universal-time)
                   :lists-checked lists)))
      (setf (gethash request-id *screening-results*) result)
      result)))

(defun screen-entity (name &key (lists '(:ofac-sdn)) (threshold 0.8))
  "Screen a business entity against sanctions lists."
  (screen-individual name :lists lists :threshold threshold))

(defun batch-screen (names &key (lists '(:ofac-sdn)) (threshold 0.8))
  "Batch screen multiple names."
  (mapcar (lambda (name)
            (screen-individual name :lists lists :threshold threshold))
          names))

(defun get-screening-result (request-id)
  "Get screening result by request ID."
  (gethash request-id *screening-results*))

;;; ============================================================================
;;; Matching Logic
;;; ============================================================================

(defun match-against-entry (request entry)
  "Match screening request against a sanctions entry."
  (let ((max-score 0.0)
        (matched-fields '()))
    ;; Match against primary names
    (dolist (entry-name (sanctions-entry-names entry))
      (let ((score (compute-name-similarity
                    (screening-request-name request)
                    entry-name)))
        (when (> score max-score)
          (setf max-score score)
          (push (list :name entry-name :score score) matched-fields))))
    ;; Match against aliases
    (dolist (alias (sanctions-entry-aliases entry))
      (let ((score (compute-name-similarity
                    (screening-request-name request)
                    alias)))
        (when (> score max-score)
          (setf max-score score)
          (push (list :alias alias :score score) matched-fields))))
    ;; Match request aliases
    (dolist (req-alias (screening-request-aliases request))
      (dolist (entry-name (sanctions-entry-names entry))
        (let ((score (compute-name-similarity req-alias entry-name)))
          (when (> score max-score)
            (setf max-score score)
            (push (list :request-alias req-alias :entry-name entry-name :score score)
                  matched-fields)))))
    ;; Create match if score is high enough
    (when (> max-score 0.5)
      (make-screening-match
       :entry-id (sanctions-entry-id entry)
       :list-id (sanctions-entry-list-id entry)
       :score max-score
       :matched-fields matched-fields
       :status :pending))))

(defun resolve-match (match resolution &key reviewer notes)
  "Resolve a screening match."
  (setf (screening-match-status match) resolution
        (screening-match-reviewed-by match) (or reviewer "")
        (screening-match-reviewed-at match) (get-universal-time))
  match)
