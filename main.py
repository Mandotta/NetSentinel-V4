# main.py - Entry point for NetSentinel v4 Windows desktop application

import sys
from PyQt6.QtWidgets import QApplication
from ui.dashboard import NetSentinelDashboard

def main():
    # Construct the QApplication context
    app = QApplication(sys.argv)
    
    # Instantiate and configure the dashboard view
    window = NetSentinelDashboard()
    window.show()
    
    # Enter application event execution loop
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
