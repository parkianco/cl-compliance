;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause

;;;; cl-compliance - Package Definition
;;;; KYC/AML Compliance Framework

(in-package #:cl-user)

(defpackage #:cl-compliance
  (:use #:cl)
  (:nicknames #:compliance)
  (:export
   ;; =========================================================================
   ;; Conditions
   ;; =========================================================================
   #:compliance-error
   #:compliance-error-code
   #:compliance-error-message
   #:identity-not-found-error
   #:verification-failed-error
   #:document-expired-error
   #:sanctions-match-error
   #:compliance-violation-error

   ;; =========================================================================
   ;; Identity Management
   ;; =========================================================================
   #:identity-record
   #:make-identity-record
   #:identity-record-id
   #:identity-record-type
   #:identity-record-attributes
   #:identity-record-verified-at
   #:identity-record-expires-at
   #:identity-record-status
   #:identity-record-risk-score

   #:identity-attribute
   #:make-identity-attribute
   #:identity-attribute-name
   #:identity-attribute-value
   #:identity-attribute-verified
   #:identity-attribute-source
   #:identity-attribute-confidence

   ;; Identity types
   #:+identity-type-individual+
   #:+identity-type-business+
   #:+identity-type-trust+
   #:+identity-type-foundation+

   ;; Verification levels
   #:+verification-level-none+
   #:+verification-level-basic+
   #:+verification-level-standard+
   #:+verification-level-enhanced+
   #:+verification-level-premium+

   ;; Identity operations
   #:identity-manager
   #:make-identity-manager
   #:create-identity
   #:update-identity
   #:get-identity
   #:delete-identity
   #:search-identities
   #:verify-identity-attribute
   #:get-identity-verification-level
   #:calculate-identity-risk-score

   ;; =========================================================================
   ;; Verification
   ;; =========================================================================
   #:verification-request
   #:make-verification-request
   #:verification-request-id
   #:verification-request-identity-id
   #:verification-request-type
   #:verification-request-status
   #:verification-request-created-at
   #:verification-request-completed-at
   #:verification-request-result

   #:submit-verification-request
   #:process-verification-request
   #:get-verification-request-status

   ;; KYC status
   #:kyc-status
   #:make-kyc-status
   #:kyc-status-identity-id
   #:kyc-status-level
   #:kyc-status-state
   #:kyc-status-checks-completed
   #:kyc-status-checks-pending
   #:kyc-status-last-updated

   ;; KYC states
   #:+kyc-state-not-started+
   #:+kyc-state-in-progress+
   #:+kyc-state-pending-review+
   #:+kyc-state-approved+
   #:+kyc-state-rejected+
   #:+kyc-state-expired+
   #:+kyc-state-suspended+

   #:get-kyc-status
   #:update-kyc-status
   #:transition-kyc-status
   #:valid-status-transition-p

   ;; =========================================================================
   ;; Document Verification
   ;; =========================================================================
   #:+document-type-passport+
   #:+document-type-national-id+
   #:+document-type-drivers-license+
   #:+document-type-residence-permit+
   #:+document-type-utility-bill+
   #:+document-type-bank-statement+

   #:verification-document
   #:make-verification-document
   #:verification-document-id
   #:verification-document-type
   #:verification-document-country
   #:verification-document-number
   #:verification-document-issue-date
   #:verification-document-expiry-date
   #:verification-document-holder-name
   #:verification-document-status

   #:document-verification-result
   #:make-document-verification-result
   #:document-verification-result-document-id
   #:document-verification-result-status
   #:document-verification-result-authenticity-score

   #:submit-document
   #:verify-document
   #:extract-document-data
   #:validate-document-format
   #:check-document-expiry
   #:compute-document-hash

   ;; =========================================================================
   ;; Sanctions Screening
   ;; =========================================================================
   #:+sanctions-list-ofac-sdn+
   #:+sanctions-list-un-consolidated+
   #:+sanctions-list-eu-consolidated+
   #:+sanctions-list-uk-consolidated+

   #:sanctions-entry
   #:make-sanctions-entry
   #:sanctions-entry-id
   #:sanctions-entry-list-id
   #:sanctions-entry-type
   #:sanctions-entry-names
   #:sanctions-entry-aliases

   #:screening-request
   #:make-screening-request
   #:screening-result
   #:make-screening-result
   #:screening-match
   #:make-screening-match

   #:screen-individual
   #:screen-entity
   #:batch-screen
   #:get-screening-result
   #:resolve-match

   ;; Fuzzy matching
   #:compute-name-similarity
   #:normalize-name
   #:generate-name-variants

   ;; =========================================================================
   ;; Transaction Monitoring
   ;; =========================================================================
   #:monitoring-rule
   #:make-monitoring-rule
   #:monitoring-rule-id
   #:monitoring-rule-name
   #:monitoring-rule-type
   #:monitoring-rule-conditions
   #:monitoring-rule-actions
   #:monitoring-rule-severity
   #:monitoring-rule-enabled

   #:+rule-type-threshold+
   #:+rule-type-velocity+
   #:+rule-type-pattern+
   #:+rule-type-behavioral+
   #:+rule-type-geographic+

   #:monitoring-alert
   #:make-monitoring-alert
   #:monitoring-alert-id
   #:monitoring-alert-rule-id
   #:monitoring-alert-transaction-id
   #:monitoring-alert-severity
   #:monitoring-alert-status

   #:+alert-status-new+
   #:+alert-status-investigating+
   #:+alert-status-escalated+
   #:+alert-status-resolved-true-positive+
   #:+alert-status-resolved-false-positive+

   #:transaction-monitor
   #:make-transaction-monitor
   #:start-transaction-monitor
   #:stop-transaction-monitor
   #:monitor-transaction
   #:process-transaction-batch

   #:add-monitoring-rule
   #:update-monitoring-rule
   #:delete-monitoring-rule
   #:get-monitoring-rules
   #:evaluate-rule

   #:create-alert
   #:assign-alert
   #:escalate-alert
   #:resolve-alert
   #:get-alerts
   #:get-pending-alerts

   ;; =========================================================================
   ;; Compliance Rule Engine
   ;; =========================================================================
   #:compliance-rule
   #:make-compliance-rule
   #:compliance-rule-id
   #:compliance-rule-name
   #:compliance-rule-jurisdiction
   #:compliance-rule-regulation
   #:compliance-rule-conditions
   #:compliance-rule-actions
   #:compliance-rule-enabled

   #:rule-condition
   #:make-rule-condition
   #:rule-action
   #:make-rule-action

   #:+action-type-require-kyc+
   #:+action-type-require-enhanced-kyc+
   #:+action-type-block-transaction+
   #:+action-type-flag-for-review+
   #:+action-type-generate-report+

   #:compliance-rule-engine
   #:make-compliance-rule-engine
   #:load-rules
   #:add-rule
   #:update-rule
   #:delete-rule
   #:enable-rule
   #:disable-rule
   #:get-rule
   #:list-rules
   #:evaluate-rules
   #:get-applicable-rules

   #:evaluate-condition
   #:execute-action

   ;; Jurisdiction
   #:jurisdiction
   #:make-jurisdiction
   #:get-jurisdiction
   #:list-jurisdictions

   ;; =========================================================================
   ;; Audit Trail
   ;; =========================================================================
   #:audit-event
   #:make-audit-event
   #:audit-event-id
   #:audit-event-timestamp
   #:audit-event-category
   #:audit-event-severity
   #:audit-event-actor
   #:audit-event-action
   #:audit-event-resource
   #:audit-event-outcome
   #:audit-event-details

   #:+severity-info+
   #:+severity-warning+
   #:+severity-error+
   #:+severity-critical+

   #:+category-authentication+
   #:+category-transaction+
   #:+category-compliance+
   #:+category-security+

   #:audit-logger
   #:make-audit-logger
   #:log-event
   #:log-compliance-event
   #:get-audit-trail
   #:search-events
   #:export-audit-trail

   ;; =========================================================================
   ;; Reporting
   ;; =========================================================================
   #:+report-type-sar+
   #:+report-type-str+
   #:+report-type-ctr+

   #:suspicious-activity-report
   #:make-suspicious-activity-report
   #:suspicious-activity-report-id
   #:suspicious-activity-report-type
   #:suspicious-activity-report-subject
   #:suspicious-activity-report-activity-description
   #:suspicious-activity-report-amount
   #:suspicious-activity-report-status

   #:create-report-draft
   #:update-report-draft
   #:submit-report-for-review
   #:approve-report
   #:reject-report
   #:file-report
   #:get-report-status

   #:generate-sar-from-alert
   #:generate-ctr
   #:search-reports
   #:export-reports

   ;; =========================================================================
   ;; Utilities
   ;; =========================================================================
   #:encrypt-pii
   #:decrypt-pii
   #:hash-pii
   #:compute-age
   #:parse-date-of-birth
   #:format-iso-date
   #:is-high-risk-country-p))

(defpackage #:cl-compliance.test
  (:use #:cl #:cl-compliance)
  (:export #:run-all-tests))
