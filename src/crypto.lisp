;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause

;;;; cl-compliance - Cryptographic Utilities
;;;; PII encryption and hashing

(in-package #:cl-compliance)

;;; ============================================================================
;;; Simple Crypto Implementation (No Dependencies)
;;; For production, replace with proper cryptographic library
;;; ============================================================================

(defparameter *pii-encryption-key* nil
  "Master key for PII encryption. Set before use.")

(defun set-encryption-key (key)
  "Set the master encryption key for PII operations."
  (setf *pii-encryption-key* key))

;;; ============================================================================
;;; SHA-256 Implementation (Simplified)
;;; ============================================================================

(defconstant +sha256-k+
  #(#x428a2f98 #x71374491 #xb5c0fbcf #xe9b5dba5
    #x3956c25b #x59f111f1 #x923f82a4 #xab1c5ed5
    #xd807aa98 #x12835b01 #x243185be #x550c7dc3
    #x72be5d74 #x80deb1fe #x9bdc06a7 #xc19bf174
    #xe49b69c1 #xefbe4786 #x0fc19dc6 #x240ca1cc
    #x2de92c6f #x4a7484aa #x5cb0a9dc #x76f988da
    #x983e5152 #xa831c66d #xb00327c8 #xbf597fc7
    #xc6e00bf3 #xd5a79147 #x06ca6351 #x14292967
    #x27b70a85 #x2e1b2138 #x4d2c6dfc #x53380d13
    #x650a7354 #x766a0abb #x81c2c92e #x92722c85
    #xa2bfe8a1 #xa81a664b #xc24b8b70 #xc76c51a3
    #xd192e819 #xd6990624 #xf40e3585 #x106aa070
    #x19a4c116 #x1e376c08 #x2748774c #x34b0bcb5
    #x391c0cb3 #x4ed8aa4a #x5b9cca4f #x682e6ff3
    #x748f82ee #x78a5636f #x84c87814 #x8cc70208
    #x90befffa #xa4506ceb #xbef9a3f7 #xc67178f2)
  "SHA-256 round constants.")

(defun sha256 (message)
  "Compute SHA-256 hash of message (byte array or string)."
  (let* ((bytes (if (stringp message)
                    (map '(vector (unsigned-byte 8)) #'char-code message)
                    message))
         (len (length bytes))
         (bit-len (* len 8))
         ;; Padding: append 1 bit, then zeros, then 64-bit length
         (padded-len (+ 64 (* 64 (ceiling (+ len 9) 64))))
         (padded (make-array padded-len :element-type '(unsigned-byte 8) :initial-element 0))
         ;; Initial hash values
         (h0 #x6a09e667) (h1 #xbb67ae85) (h2 #x3c6ef372) (h3 #xa54ff53a)
         (h4 #x510e527f) (h5 #x9b05688c) (h6 #x1f83d9ab) (h7 #x5be0cd19))

    ;; Copy message and add padding
    (replace padded bytes)
    (setf (aref padded len) #x80)

    ;; Append bit length (big-endian, 64 bits)
    (loop for i from 0 below 8
          do (setf (aref padded (- padded-len 1 i))
                   (ldb (byte 8 (* i 8)) bit-len)))

    ;; Process 512-bit blocks
    (loop for block-start from 0 below padded-len by 64
          do (let ((w (make-array 64 :element-type '(unsigned-byte 32))))
               ;; Prepare message schedule
               (loop for i from 0 below 16
                     do (setf (aref w i)
                              (logior (ash (aref padded (+ block-start (* i 4))) 24)
                                      (ash (aref padded (+ block-start (* i 4) 1)) 16)
                                      (ash (aref padded (+ block-start (* i 4) 2)) 8)
                                      (aref padded (+ block-start (* i 4) 3)))))

               ;; Extend message schedule
               (loop for i from 16 below 64
                     do (let* ((s0 (logxor (sha256-rotr (aref w (- i 15)) 7)
                                           (sha256-rotr (aref w (- i 15)) 18)
                                           (ash (aref w (- i 15)) -3)))
                               (s1 (logxor (sha256-rotr (aref w (- i 2)) 17)
                                           (sha256-rotr (aref w (- i 2)) 19)
                                           (ash (aref w (- i 2)) -10))))
                          (setf (aref w i)
                                (ldb (byte 32 0)
                                     (+ (aref w (- i 16)) s0 (aref w (- i 7)) s1)))))

               ;; Compression
               (let ((a h0) (b h1) (c h2) (d h3) (e h4) (f h5) (g h6) (h h7))
                 (loop for i from 0 below 64
                       do (let* ((s1 (logxor (sha256-rotr e 6) (sha256-rotr e 11) (sha256-rotr e 25)))
                                 (ch (logxor (logand e f) (logand (lognot e) g)))
                                 (temp1 (ldb (byte 32 0) (+ h s1 ch (aref +sha256-k+ i) (aref w i))))
                                 (s0 (logxor (sha256-rotr a 2) (sha256-rotr a 13) (sha256-rotr a 22)))
                                 (maj (logxor (logand a b) (logand a c) (logand b c)))
                                 (temp2 (ldb (byte 32 0) (+ s0 maj))))
                            (setf h g
                                 g f
                                 f e
                                 e (ldb (byte 32 0) (+ d temp1))
                                 d c
                                 c b
                                 b a
                                 a (ldb (byte 32 0) (+ temp1 temp2)))))

                 (setf h0 (ldb (byte 32 0) (+ h0 a))
                       h1 (ldb (byte 32 0) (+ h1 b))
                       h2 (ldb (byte 32 0) (+ h2 c))
                       h3 (ldb (byte 32 0) (+ h3 d))
                       h4 (ldb (byte 32 0) (+ h4 e))
                       h5 (ldb (byte 32 0) (+ h5 f))
                       h6 (ldb (byte 32 0) (+ h6 g))
                       h7 (ldb (byte 32 0) (+ h7 h))))))

    ;; Produce final hash
    (let ((hash (make-array 32 :element-type '(unsigned-byte 8))))
      (loop for (val offset) in (list (list h0 0) (list h1 4) (list h2 8) (list h3 12)
                                       (list h4 16) (list h5 20) (list h6 24) (list h7 28))
            do (loop for i from 0 below 4
                     do (setf (aref hash (+ offset i))
                              (ldb (byte 8 (- 24 (* i 8))) val))))
      hash)))

(defun sha256-rotr (x n)
  "Right rotate 32-bit integer X by N bits."
  (logior (ldb (byte 32 0) (ash x (- n)))
          (ldb (byte 32 0) (ash x (- 32 n)))))

;;; ============================================================================
;;; PII Encryption/Hashing
;;; ============================================================================

(defun hash-pii (data)
  "Hash PII data using SHA-256. Returns hex string."
  (let* ((bytes (if (stringp data)
                    (map '(vector (unsigned-byte 8)) #'char-code data)
                    data))
         (hash (sha256 bytes)))
    (bytes-to-hex hash)))

(defun encrypt-pii (plaintext)
  "Encrypt PII data. Returns encrypted bytes.
   Note: Uses XOR with key for demonstration. Use AES-256-GCM in production."
  (unless *pii-encryption-key*
    (error 'compliance-error
           :code :no-encryption-key
           :message "PII encryption key not set"))
  (let* ((bytes (if (stringp plaintext)
                    (map '(vector (unsigned-byte 8)) #'char-code plaintext)
                    plaintext))
         (key-hash (sha256 *pii-encryption-key*))
         (encrypted (make-array (length bytes) :element-type '(unsigned-byte 8))))
    (loop for i from 0 below (length bytes)
          do (setf (aref encrypted i)
                   (logxor (aref bytes i)
                           (aref key-hash (mod i 32)))))
    encrypted))

(defun decrypt-pii (ciphertext)
  "Decrypt PII data. Returns plaintext bytes."
  ;; XOR encryption is symmetric
  (encrypt-pii ciphertext))

(defun bytes-to-hex (bytes)
  "Convert byte array to hex string."
  (with-output-to-string (s)
    (loop for byte across bytes
          do (format s "~2,'0X" byte))))

(defun hex-to-bytes (hex)
  "Convert hex string to byte array."
  (let* ((len (/ (length hex) 2))
         (bytes (make-array len :element-type '(unsigned-byte 8))))
    (loop for i from 0 below len
          do (setf (aref bytes i)
                   (parse-integer hex :start (* i 2) :end (* i 2 2) :radix 16)))
    bytes))
