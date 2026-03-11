;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause

;;;; cl-compliance - Compliance Rule Engine
;;;; Rule definitions, evaluation, and jurisdictions

(in-package #:cl-compliance)

;;; ============================================================================
;;; Action Types
;;; ============================================================================

(defconstant +action-type-require-kyc+ :require-kyc)
(defconstant +action-type-require-enhanced-kyc+ :require-enhanced-kyc)
(defconstant +action-type-block-transaction+ :block-transaction)
(defconstant +action-type-flag-for-review+ :flag-for-review)
(defconstant +action-type-generate-report+ :generate-report)

;;; ============================================================================
;;; Rule Structures
;;; ============================================================================

(defstruct rule-condition
  "A condition in a compliance rule."
  (type :simple :type keyword)
  (field "" :type string)
  (operator :eq :type keyword)
  (value nil)
  (children '() :type list))

(defstruct rule-action
  "An action to execute when rule matches."
  (type :flag-for-review :type keyword)
  (parameters (make-hash-table :test 'equal) :type hash-table))

(defstruct compliance-rule
  "A compliance rule definition."
  (id "" :type string)
  (name "" :type string)
  (description "" :type string)
  (jurisdiction "" :type string)
  (regulation "" :type string)
  (effective-date 0 :type integer)
  (expiry-date 0 :type integer)
  (conditions '() :type list)
  (actions '() :type list)
  (priority 100 :type integer)
  (enabled t :type boolean)
  (created-at 0 :type integer)
  (updated-at 0 :type integer))

(defstruct jurisdiction
  "A regulatory jurisdiction."
  (code "" :type string)
  (name "" :type string)
  (regulations '() :type list)
  (requirements '() :type list))

;;; ============================================================================
;;; Rule Engine
;;; ============================================================================

(defstruct compliance-rule-engine
  "The compliance rule engine."
  (rules (make-hash-table :test 'equal) :type hash-table)
  (jurisdictions (make-hash-table :test 'equal) :type hash-table)
  (config (make-hash-table :test 'equal) :type hash-table))

;;; ============================================================================
;;; Rule Management
;;; ============================================================================

(defun load-rules (engine rules)
  "Load rules into the engine."
  (dolist (rule rules)
    (add-rule engine rule))
  (hash-table-count (compliance-rule-engine-rules engine)))

(defun add-rule (engine rule)
  "Add a rule to the engine."
  (when (string= (compliance-rule-id rule) "")
    (setf (compliance-rule-id rule) (generate-uuid)))
  (setf (compliance-rule-created-at rule) (get-universal-time)
        (compliance-rule-updated-at rule) (get-universal-time))
  (setf (gethash (compliance-rule-id rule)
                 (compliance-rule-engine-rules engine))
        rule)
  rule)

(defun update-rule (engine rule-id &key name conditions actions priority enabled)
  "Update a rule."
  (let ((rule (gethash rule-id (compliance-rule-engine-rules engine))))
    (unless rule
      (error 'compliance-error
             :code :rule-not-found
             :message "Compliance rule not found"))
    (when name (setf (compliance-rule-name rule) name))
    (when conditions (setf (compliance-rule-conditions rule) conditions))
    (when actions (setf (compliance-rule-actions rule) actions))
    (when priority (setf (compliance-rule-priority rule) priority))
    (when (not (null enabled)) (setf (compliance-rule-enabled rule) enabled))
    (setf (compliance-rule-updated-at rule) (get-universal-time))
    rule))

(defun delete-rule (engine rule-id)
  "Delete a rule."
  (remhash rule-id (compliance-rule-engine-rules engine)))

(defun enable-rule (engine rule-id)
  "Enable a rule."
  (let ((rule (gethash rule-id (compliance-rule-engine-rules engine))))
    (when rule
      (setf (compliance-rule-enabled rule) t))))

(defun disable-rule (engine rule-id)
  "Disable a rule."
  (let ((rule (gethash rule-id (compliance-rule-engine-rules engine))))
    (when rule
      (setf (compliance-rule-enabled rule) nil))))

(defun get-rule (engine rule-id)
  "Get a rule by ID."
  (gethash rule-id (compliance-rule-engine-rules engine)))

(defun list-rules (engine &key jurisdiction regulation enabled)
  "List rules with optional filters."
  (let ((rules '()))
    (maphash (lambda (id rule)
               (declare (ignore id))
               (when (and (or (null jurisdiction)
                              (string= (compliance-rule-jurisdiction rule) jurisdiction))
                          (or (null regulation)
                              (string= (compliance-rule-regulation rule) regulation))
                          (or (null enabled)
                              (eq (compliance-rule-enabled rule) enabled)))
                 (push rule rules)))
             (compliance-rule-engine-rules engine))
    ;; Sort by priority (lower number = higher priority)
    (sort rules #'< :key #'compliance-rule-priority)))

;;; ============================================================================
;;; Rule Evaluation
;;; ============================================================================

(defun evaluate-rules (engine context)
  "Evaluate all applicable rules against a context."
  (let ((results '())
        (rules (get-applicable-rules engine context)))
    (dolist (rule rules)
      (when (compliance-rule-enabled rule)
        (let ((matched (evaluate-rule-conditions rule context)))
          (when matched
            (push (list :rule rule
                        :matched t
                        :actions (compliance-rule-actions rule))
                  results)))))
    results))

(defun get-applicable-rules (engine context)
  "Get rules applicable to the given context."
  (let ((jurisdiction (getf context :jurisdiction))
        (rules '()))
    (maphash (lambda (id rule)
               (declare (ignore id))
               (when (or (string= (compliance-rule-jurisdiction rule) "")
                         (null jurisdiction)
                         (string= (compliance-rule-jurisdiction rule) jurisdiction))
                 (push rule rules)))
             (compliance-rule-engine-rules engine))
    (sort rules #'< :key #'compliance-rule-priority)))

(defun evaluate-rule-conditions (rule context)
  "Evaluate all conditions of a rule."
  (let ((conditions (compliance-rule-conditions rule)))
    (if (null conditions)
        t ; No conditions = always match
        (every (lambda (condition)
                 (evaluate-condition condition context))
               conditions))))

(defun evaluate-condition (condition context)
  "Evaluate a single condition."
  (let ((type (rule-condition-type condition)))
    (case type
      (:and (every (lambda (c) (evaluate-condition c context))
                   (rule-condition-children condition)))
      (:or (some (lambda (c) (evaluate-condition c context))
                 (rule-condition-children condition)))
      (:not (not (evaluate-condition (first (rule-condition-children condition)) context)))
      (otherwise (evaluate-simple-condition condition context)))))

(defun evaluate-simple-condition (condition context)
  "Evaluate a simple field comparison condition."
  (let* ((field (intern (string-upcase (rule-condition-field condition)) :keyword))
         (operator (rule-condition-operator condition))
         (expected (rule-condition-value condition))
         (actual (getf context field)))
    (case operator
      (:eq (equal actual expected))
      (:neq (not (equal actual expected)))
      (:gt (and (numberp actual) (> actual expected)))
      (:gte (and (numberp actual) (>= actual expected)))
      (:lt (and (numberp actual) (< actual expected)))
      (:lte (and (numberp actual) (<= actual expected)))
      (:contains (and (stringp actual) (search expected actual)))
      (:in (member actual expected :test #'equal))
      (:regex (and (stringp actual) (search expected actual)))
      (otherwise nil))))

;;; ============================================================================
;;; Action Execution
;;; ============================================================================

(defun execute-action (action context)
  "Execute a rule action."
  (let ((type (rule-action-type action))
        (params (rule-action-parameters action)))
    (case type
      (:require-kyc
       (list :action :require-kyc
             :level (or (gethash "level" params) +verification-level-basic+)))
      (:require-enhanced-kyc
       (list :action :require-enhanced-kyc
             :level +verification-level-enhanced+))
      (:block-transaction
       (list :action :block
             :reason (or (gethash "reason" params) "Compliance rule violation")))
      (:flag-for-review
       (list :action :flag
             :priority (or (gethash "priority" params) :medium)))
      (:generate-report
       (list :action :report
             :type (or (gethash "report-type" params) :sar)))
      (otherwise
       (list :action :unknown :type type)))))

;;; ============================================================================
;;; Jurisdiction Management
;;; ============================================================================

(defun get-jurisdiction (engine code)
  "Get jurisdiction by code."
  (gethash code (compliance-rule-engine-jurisdictions engine)))

(defun list-jurisdictions (engine)
  "List all jurisdictions."
  (let ((jurisdictions '()))
    (maphash (lambda (code jurisdiction)
               (declare (ignore code))
               (push jurisdiction jurisdictions))
             (compliance-rule-engine-jurisdictions engine))
    jurisdictions))
