from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QLabel, QLineEdit,
    QDialogButtonBox, QMessageBox
)
from PyQt5.QtCore import Qt

class MonitoringReasonDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Monitoring Reason")
        self.setFixedSize(400, 200)
        
        layout = QVBoxLayout()
        
        # Add description label
        description = QLabel(
            "Please provide a reason for monitoring system calls.\n"
            "This will be logged for security purposes."
        )
        description.setWordWrap(True)
        layout.addWidget(description)
        
        # Add reason input field
        self.reason_input = QLineEdit()
        self.reason_input.setPlaceholderText("Enter monitoring reason...")
        layout.addWidget(self.reason_input)
        
        # Add buttons
        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | 
            QDialogButtonBox.StandardButton.Cancel
        )
        button_box.accepted.connect(self.validate_and_accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
        
        self.setLayout(layout)
        
    def validate_and_accept(self):
        reason = self.reason_input.text().strip()
        if not reason:
            QMessageBox.warning(
                self,
                "Invalid Input",
                "Please provide a reason for monitoring."
            )
            return
        self.accept()
        
    def get_reason(self):
        return self.reason_input.text().strip()
