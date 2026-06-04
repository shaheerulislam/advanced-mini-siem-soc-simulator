from siem_engine import load_logs, process_logs, save_alerts

def main():
    logs = load_logs()
    process_logs(logs)
    save_alerts()

    print("\nSOC Attack Simulation Completed Successfully.")

if __name__ == "__main__":
    main()
