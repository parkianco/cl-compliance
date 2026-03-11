;;;; cl-compliance - Compliance Reporting
;;;; SAR/STR/CTR report generation and filing

(in-package #:cl-compliance)

;;; ============================================================================
;;; Report Types
;;; ============================================================================

(defconstant +report-type-sar+ :sar
  "Suspicious Activity Report.")

(defconstant +report-type-str+ :str
  "Suspicious Transaction Report.")

(defconstant +report-type-ctr+ :ctr
  "Currency Transaction Report.")

;;; ============================================================================
;;; Report Structures
;;; ============================================================================

(defstruct suspicious-activity-report
  "A Suspicious Activity Report (SAR)."
  (id "" :type string)
  (type :sar :type keyword)
  (filing-institution "" :type string)
  (subject nil)
  (activity-description "" :type string)
  (amount 0 :type number)
  (activity-dates '() :type list)
  (suspicious-indicators '() :type list)
  (supporting-documents '() :type list)
  (created-at 0 :type integer)
  (submitted-at 0 :type integer)
  (status :draft :type keyword)
  (reference-number "" :type string)
  (reviewer "" :type string)
  (approved-at 0 :type integer))

(defstruct report-subject
  "Subject of a compliance report."
  (type :individual :type keyword)
  (identity-id "" :type string)
  (name "" :type string)
  (identifiers '() :type list)
  (addresses '() :type list)
  (account-numbers '() :type list)
  (relationship "" :type string))

;;; ============================================================================
;;; Report Storage
;;; ============================================================================

(defparameter *report-store* (make-hash-table :test 'equal)
  "Storage for compliance reports.")

;;; ============================================================================
;;; Report Creation
;;; ============================================================================

(defun create-report-draft (type &key filing-institution subject activity-description
                                      amount activity-dates indicators)
  "Create a new report draft."
  (let ((report (make-suspicious-activity-report
                 :id (generate-uuid)
                 :type type
                 :filing-institution (or filing-institution "")
                 :subject subject
                 :activity-description (or activity-description "")
                 :amount (or amount 0)
                 :activity-dates (or activity-dates '())
                 :suspicious-indicators (or indicators '())
                 :status :draft
                 :created-at (get-universal-time))))
    (setf (gethash (suspicious-activity-report-id report) *report-store*) report)
    ;; Log audit event
    (log-compliance-event "create-report"
                          (suspicious-activity-report-id report)
                          :details (list :type type))
    report))

(defun update-report-draft (report-id &key activity-description amount indicators
                                           supporting-documents)
  "Update a report draft."
  (let ((report (gethash report-id *report-store*)))
    (unless report
      (error 'compliance-error
             :code :report-not-found
             :message "Report not found"))
    (unless (eq (suspicious-activity-report-status report) :draft)
      (error 'compliance-error
             :code :invalid-status
             :message "Can only update draft reports"))
    (when activity-description
      (setf (suspicious-activity-report-activity-description report)
            activity-description))
    (when amount
      (setf (suspicious-activity-report-amount report) amount))
    (when indicators
      (setf (suspicious-activity-report-suspicious-indicators report) indicators))
    (when supporting-documents
      (setf (suspicious-activity-report-supporting-documents report)
            supporting-documents))
    report))

;;; ============================================================================
;;; Report Workflow
;;; ============================================================================

(defun submit-report-for-review (report-id)
  "Submit a report for review."
  (let ((report (gethash report-id *report-store*)))
    (unless report
      (error 'compliance-error :code :report-not-found))
    (unless (eq (suspicious-activity-report-status report) :draft)
      (error 'compliance-error :code :invalid-status))
    (setf (suspicious-activity-report-status report) :pending-review)
    (log-compliance-event "submit-for-review" report-id)
    report))

(defun approve-report (report-id reviewer)
  "Approve a report."
  (let ((report (gethash report-id *report-store*)))
    (unless report
      (error 'compliance-error :code :report-not-found))
    (unless (eq (suspicious-activity-report-status report) :pending-review)
      (error 'compliance-error :code :invalid-status))
    (setf (suspicious-activity-report-status report) :approved
          (suspicious-activity-report-reviewer report) reviewer
          (suspicious-activity-report-approved-at report) (get-universal-time))
    (log-compliance-event "approve-report" report-id
                          :actor reviewer)
    report))

(defun reject-report (report-id reviewer &key reason)
  "Reject a report."
  (let ((report (gethash report-id *report-store*)))
    (unless report
      (error 'compliance-error :code :report-not-found))
    (setf (suspicious-activity-report-status report) :rejected
          (suspicious-activity-report-reviewer report) reviewer)
    (log-compliance-event "reject-report" report-id
                          :actor reviewer
                          :details (list :reason reason))
    report))

(defun file-report (report-id)
  "File a report with regulatory authority."
  (let ((report (gethash report-id *report-store*)))
    (unless report
      (error 'compliance-error :code :report-not-found))
    (unless (eq (suspicious-activity-report-status report) :approved)
      (error 'compliance-error
             :code :invalid-status
             :message "Report must be approved before filing"))
    ;; Generate reference number
    (setf (suspicious-activity-report-reference-number report)
          (format nil "~A-~A-~6,'0D"
                  (suspicious-activity-report-type report)
                  (format-iso-date (get-universal-time))
                  (random 1000000))
          (suspicious-activity-report-submitted-at report) (get-universal-time)
          (suspicious-activity-report-status report) :filed)
    (log-compliance-event "file-report" report-id
                          :details (list :reference
                                         (suspicious-activity-report-reference-number report)))
    report))

(defun get-report-status (report-id)
  "Get status of a report."
  (let ((report (gethash report-id *report-store*)))
    (when report
      (suspicious-activity-report-status report))))

;;; ============================================================================
;;; Report Generation
;;; ============================================================================

(defun generate-sar-from-alert (alert)
  "Generate SAR from monitoring alert."
  (create-report-draft
   :sar
   :activity-description (format nil "Alert: ~A"
                                 (monitoring-alert-rule-id alert))
   :indicators (list (monitoring-alert-details alert))))

(defun generate-ctr (identity-id amount date &key description)
  "Generate Currency Transaction Report."
  (create-report-draft
   :ctr
   :amount amount
   :activity-dates (list date)
   :activity-description (or description
                             (format nil "Currency transaction of ~A" amount))))

;;; ============================================================================
;;; Report Queries
;;; ============================================================================

(defun search-reports (&key type status subject-id start-date end-date)
  "Search reports with filters."
  (let ((results '()))
    (maphash (lambda (id report)
               (declare (ignore id))
               (when (and (or (null type)
                              (eq (suspicious-activity-report-type report) type))
                          (or (null status)
                              (eq (suspicious-activity-report-status report) status))
                          (or (null subject-id)
                              (and (suspicious-activity-report-subject report)
                                   (string= (report-subject-identity-id
                                             (suspicious-activity-report-subject report))
                                            subject-id)))
                          (or (null start-date)
                              (>= (suspicious-activity-report-created-at report)
                                  start-date))
                          (or (null end-date)
                              (<= (suspicious-activity-report-created-at report)
                                  end-date)))
                 (push report results)))
             *report-store*)
    results))

(defun export-reports (reports &key (format :json))
  "Export reports to specified format."
  (case format
    (:json (export-reports-json reports))
    (:csv (export-reports-csv reports))
    (otherwise reports)))

(defun export-reports-json (reports)
  "Export reports to JSON."
  (with-output-to-string (s)
    (write-char #\[ s)
    (loop for report in reports
          for first = t then nil
          do (unless first (write-char #\, s))
             (format s "{\"id\":\"~A\",\"type\":\"~A\",\"status\":\"~A\",\"amount\":~A,\"reference\":\"~A\"}"
                     (suspicious-activity-report-id report)
                     (suspicious-activity-report-type report)
                     (suspicious-activity-report-status report)
                     (suspicious-activity-report-amount report)
                     (suspicious-activity-report-reference-number report)))
    (write-char #\] s)))

(defun export-reports-csv (reports)
  "Export reports to CSV."
  (with-output-to-string (s)
    (format s "id,type,status,amount,reference,created_at~%")
    (dolist (report reports)
      (format s "~A,~A,~A,~A,~A,~D~%"
              (suspicious-activity-report-id report)
              (suspicious-activity-report-type report)
              (suspicious-activity-report-status report)
              (suspicious-activity-report-amount report)
              (suspicious-activity-report-reference-number report)
              (suspicious-activity-report-created-at report)))))
