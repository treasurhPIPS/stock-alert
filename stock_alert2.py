import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
import random

# --- Stock and Alert Classes ---

class Stock:
    """Represents a stock with its symbol and current price."""
    def __init__(self, symbol: str):
        self.symbol = symbol.upper()
        self._current_price = 0.0 # Will be updated by the monitor

    def get_current_price(self) -> float:
        """
        Retrieves the current price of the stock.
        In a real application, this would call a stock market API.
        For this example, it simulates price fluctuation.
        """
        # --- IMPORTANT: Placeholder for real stock price API ---
        # You would replace this with an actual API call (e.g., Alpha Vantage, Yahoo Finance, etc.)
        # Example using a dummy fluctuating price:
        if self._current_price == 0.0:
            # Initialize with a base price if not set
            self._current_price = random.uniform(100.0, 500.0)

        # Simulate price fluctuation around the current price
        fluctuation = random.uniform(-5.0, 5.0)
        self._current_price += fluctuation
        # Ensure price doesn't go below a reasonable minimum
        if self._current_price < 1.0:
            self._current_price = 1.0
        return round(self._current_price, 2)

class Alert:
    """Represents a price alert for a specific stock."""
    def __init__(self, stock_symbol: str, target_price: float, condition: str):
        self.stock_symbol = stock_symbol.upper()
        self.target_price = target_price
        self.condition = condition # 'above' or 'below'
        self.triggered = False # To track if the alert has been triggered

    def check(self, current_price: float) -> bool:
        """
        Checks if the alert condition is met.
        Returns True if triggered, False otherwise.
        """
        if self.condition == 'above':
            return current_price >= self.target_price
        elif self.condition == 'below':
            return current_price <= self.target_price
        return False

# --- Main GUI Application Class ---

class StockMonitorApp:
    """Main application class for the stock price monitor GUI."""
    def __init__(self, master: tk.Tk):
        self.master = master
        master.title("Stock Price Alert System")
        master.geometry("800x600")
        master.resizable(True, True) # Allow window resizing

        self.stocks = {}  # Dictionary to store Stock objects: {symbol: Stock_object}
        self.alerts = []  # List to store Alert objects

        self.monitoring_thread = None
        self.running_monitor = False

        # Predefined list of popular stocks
        self.predefined_stocks = {
            "AAPL": "Apple Inc.",
            "MSFT": "Microsoft Corp.",
            "GOOGL": "Alphabet Inc. (Class A)",
            "AMZN": "Amazon.com Inc.",
            "NVDA": "NVIDIA Corp.",
            "TSLA": "Tesla Inc.",
            "META": "Meta Platforms Inc.",
            "BRK.B": "Berkshire Hathaway Inc. (Class B)",
            "JPM": "JPMorgan Chase & Co.",
            "V": "Visa Inc.",
            "JNJ": "Johnson & Johnson",
            "UNH": "UnitedHealth Group Inc.",
            "XOM": "Exxon Mobil Corp.",
            "PG": "Procter & Gamble Co.",
            "HD": "The Home Depot Inc.",
            "KO": "The Coca-Cola Co."
        }
        # Create a list of "Symbol - Name" for the combobox
        self.stock_options = [f"{symbol} - {name}" for symbol, name in self.predefined_stocks.items()]
        self.stock_options.sort() # Sort alphabetically

        self._create_widgets()
        self._setup_layout()

        # Handle window closing event to stop the monitoring thread
        master.protocol("WM_DELETE_WINDOW", self._on_closing)

    def _create_widgets(self):
        """Creates all the GUI elements."""
        # --- Input Frame ---
        self.input_frame = ttk.LabelFrame(self.master, text="Add New Alert", padding="10 10 10 10")
        self.input_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        ttk.Label(self.input_frame, text="Select Stock:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.symbol_combobox = ttk.Combobox(self.input_frame, values=self.stock_options, state="readonly", width=30)
        self.symbol_combobox.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        self.symbol_combobox.set("Select a stock...") # Default text
        # Allow typing in the combobox to filter, but still restrict to predefined values
        self.symbol_combobox.bind("<<ComboboxSelected>>", self._on_stock_selected)


        ttk.Label(self.input_frame, text="Target Price:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.price_entry = ttk.Entry(self.input_frame, width=20)
        self.price_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")

        ttk.Label(self.input_frame, text="Condition:").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.condition_var = tk.StringVar(value='above')
        self.above_radio = ttk.Radiobutton(self.input_frame, text="Above or Equal", variable=self.condition_var, value='above')
        self.above_radio.grid(row=2, column=1, padx=5, pady=2, sticky="w")
        self.below_radio = ttk.Radiobutton(self.input_frame, text="Below or Equal", variable=self.condition_var, value='below')
        self.below_radio.grid(row=3, column=1, padx=5, pady=2, sticky="w")

        self.add_button = ttk.Button(self.input_frame, text="Add Alert", command=self._add_alert)
        self.add_button.grid(row=4, column=0, columnspan=2, pady=10)

        # Configure column weights for input frame
        self.input_frame.grid_columnconfigure(1, weight=1)

        # --- Alerts Display Frame ---
        self.alerts_frame = ttk.LabelFrame(self.master, text="Active Alerts", padding="10 10 10 10")
        self.alerts_frame.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")

        self.alert_tree = ttk.Treeview(self.alerts_frame, columns=("Symbol", "Target Price", "Condition", "Current Price", "Status"), show="headings")
        self.alert_tree.heading("Symbol", text="Symbol")
        self.alert_tree.heading("Target Price", text="Target Price")
        self.alert_tree.heading("Condition", text="Condition")
        self.alert_tree.heading("Current Price", text="Current Price")
        self.alert_tree.heading("Status", text="Status")

        # Set column widths
        self.alert_tree.column("Symbol", width=80, anchor="center")
        self.alert_tree.column("Target Price", width=100, anchor="center")
        self.alert_tree.column("Condition", width=80, anchor="center")
        self.alert_tree.column("Current Price", width=100, anchor="center")
        self.alert_tree.column("Status", width=100, anchor="center")

        self.alert_tree.grid(row=0, column=0, sticky="nsew")

        # Scrollbar for the treeview
        self.tree_scrollbar = ttk.Scrollbar(self.alerts_frame, orient="vertical", command=self.alert_tree.yview)
        self.alert_tree.configure(yscrollcommand=self.tree_scrollbar.set)
        self.tree_scrollbar.grid(row=0, column=1, sticky="ns")

        self.remove_button = ttk.Button(self.alerts_frame, text="Remove Selected Alert", command=self._remove_alert)
        self.remove_button.grid(row=1, column=0, columnspan=2, pady=10)

        # Configure row and column weights for alerts frame
        self.alerts_frame.grid_rowconfigure(0, weight=1)
        self.alerts_frame.grid_columnconfigure(0, weight=1)

        # --- Status/Alert Message Frame ---
        self.status_frame = ttk.LabelFrame(self.master, text="Status", padding="10 10 10 10")
        self.status_frame.grid(row=2, column=0, padx=10, pady=10, sticky="ew")

        self.status_label = ttk.Label(self.status_frame, text="Ready to monitor stocks.", foreground="blue")
        self.status_label.pack(fill="x", expand=True)

        # --- Global Layout Configuration ---
        self.master.grid_rowconfigure(1, weight=1) # Allow alerts frame to expand vertically
        self.master.grid_columnconfigure(0, weight=1) # Allow content to expand horizontally

    def _setup_layout(self):
        """Sets up the overall layout of the application."""
        # Padding and styling can be further enhanced here
        s = ttk.Style()
        s.configure('TFrame', background='#f0f0f0')
        s.configure('TLabelFrame', background='#f0f0f0', foreground='darkblue', font=('Arial', 10, 'bold'))
        s.configure('TLabel', background='#f0f0f0')
        s.configure('TButton', font=('Arial', 10))
        s.configure('Treeview.Heading', font=('Arial', 10, 'bold'))
        s.configure('Treeview', font=('Arial', 10), rowheight=25)

    def _on_stock_selected(self, event):
        """Handles selection from the combobox."""
        # When a stock is selected, we might want to do something,
        # but for now, just ensure the combobox value is set.
        pass

    def _add_alert(self):
        """Adds a new alert based on user input."""
        selected_stock_text = self.symbol_combobox.get().strip()
        # Extract symbol from "Symbol - Name" format
        if " - " in selected_stock_text:
            symbol = selected_stock_text.split(" - ")[0].upper()
        else:
            # If user typed something not in the list, try to use it directly as symbol
            symbol = selected_stock_text.upper()

        price_str = self.price_entry.get().strip()
        condition = self.condition_var.get()

        if not symbol or symbol == "SELECT A STOCK...": # Check for default text
            messagebox.showerror("Input Error", "Please select a Stock Symbol or enter a valid one.")
            return
        try:
            target_price = float(price_str)
            if target_price <= 0:
                messagebox.showerror("Input Error", "Target Price must be a positive number.")
                return
        except ValueError:
            messagebox.showerror("Input Error", "Target Price must be a valid number.")
            return

        # Check if stock already exists, otherwise create a new one
        if symbol not in self.stocks:
            self.stocks[symbol] = Stock(symbol)

        new_alert = Alert(symbol, target_price, condition)
        self.alerts.append(new_alert)
        self._update_alert_display()
        self.status_label.config(text=f"Alert added for {symbol} at {target_price} ({condition}).", foreground="green")

        # Clear input fields and reset combobox
        self.symbol_combobox.set("Select a stock...")
        self.price_entry.delete(0, tk.END)

        # Start monitoring if not already running
        if not self.running_monitor:
            self._start_monitoring()

    def _remove_alert(self):
        """Removes the selected alert from the list."""
        selected_item = self.alert_tree.selection()
        if not selected_item:
            messagebox.showwarning("Selection Error", "Please select an alert to remove.")
            return

        # Get the values of the selected item
        item_values = self.alert_tree.item(selected_item, 'values')
        if not item_values:
            return # Should not happen if an item is selected

        symbol_to_remove = item_values[0]
        target_price_to_remove = float(item_values[1])
        condition_to_remove = item_values[2]

        alert_found = False
        for i, alert in enumerate(self.alerts):
            if (alert.stock_symbol == symbol_to_remove and
                alert.target_price == target_price_to_remove and
                alert.condition == condition_to_remove):
                del self.alerts[i]
                alert_found = True
                break

        if alert_found:
            self._update_alert_display()
            self.status_label.config(text=f"Alert for {symbol_to_remove} at {target_price_to_remove} removed.", foreground="orange")
        else:
            self.status_label.config(text="Could not find the selected alert to remove.", foreground="red")


        # If no more alerts, consider stopping the monitor
        if not self.alerts and self.running_monitor:
            self._stop_monitoring()
            self.status_label.config(text="All alerts removed. Monitoring stopped.", foreground="blue")


    def _update_alert_display(self):
        """Refreshes the Treeview display with current alerts and prices."""
        # Clear existing items
        for item in self.alert_tree.get_children():
            self.alert_tree.delete(item)

        # Insert current alerts
        for alert in self.alerts:
            stock = self.stocks.get(alert.stock_symbol)
            current_price = stock.get_current_price() if stock else "N/A"
            status = "Triggered!" if alert.triggered else "Active"
            self.alert_tree.insert("", "end", values=(alert.stock_symbol, alert.target_price, alert.condition, current_price, status))

    def _start_monitoring(self):
        """Starts the background thread for monitoring stock prices."""
        if not self.running_monitor:
            self.running_monitor = True
            self.monitoring_thread = threading.Thread(target=self._monitor_prices_loop, daemon=True)
            self.monitoring_thread.start()
            self.status_label.config(text="Monitoring started...", foreground="blue")

    def _stop_monitoring(self):
        """Stops the background thread."""
        if self.running_monitor:
            self.running_monitor = False
            # Give the thread a moment to finish its current iteration
            if self.monitoring_thread and self.monitoring_thread.is_alive():
                self.monitoring_thread.join(timeout=1) # Wait for max 1 second
            self.status_label.config(text="Monitoring stopped.", foreground="red")

    def _monitor_prices_loop(self):
        """
        The main loop that runs in a separate thread to check stock prices
        and trigger alerts.
        """
        while self.running_monitor:
            if not self.alerts:
                # If no alerts, stop the monitoring loop
                self.running_monitor = False
                self.master.after(0, lambda: self.status_label.config(text="No active alerts. Monitoring paused.", foreground="blue"))
                break

            for alert in list(self.alerts): # Iterate over a copy to allow modification during iteration
                stock = self.stocks.get(alert.stock_symbol)
                if stock:
                    current_price = stock.get_current_price()
                    # Update the current price in the display immediately
                    self.master.after(0, self._update_alert_display) # Schedule GUI update on main thread

                    if not alert.triggered and alert.check(current_price):
                        alert.triggered = True # Mark as triggered
                        message = f"ALERT! {alert.stock_symbol} hit {current_price} (Target: {alert.target_price} {alert.condition})."
                        # Use master.after to safely update GUI from a different thread
                        self.master.after(0, lambda msg=message: self._show_alert_message(msg))
                        self.master.after(0, self._update_alert_display) # Update display to show "Triggered!"
                else:
                    # This case should ideally not happen if stocks are managed correctly
                    self.master.after(0, lambda s=alert.stock_symbol: self.status_label.config(text=f"Error: Stock {s} not found.", foreground="red"))

            time.sleep(5) # Check every 5 seconds (adjust as needed)

    def _show_alert_message(self, message: str):
        """Displays an alert message in the status bar and as a messagebox."""
        self.status_label.config(text=message, foreground="red", font=('Arial', 10, 'bold'))
        messagebox.showinfo("Stock Alert!", message)

    def _on_closing(self):
        """Handles the window closing event to ensure graceful shutdown."""
        if messagebox.askokcancel("Quit", "Do you want to quit and stop monitoring?"):
            self._stop_monitoring() # Stop the background thread
            self.master.destroy() # Close the Tkinter window

# --- Main execution block ---
if __name__ == "__main__":
    root = tk.Tk()
    app = StockMonitorApp(root)
    root.mainloop()
