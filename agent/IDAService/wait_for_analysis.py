import ida_auto
import os
import ida_nalt
import idc

def main():
    # Wait for auto-analysis to finish
    ida_auto.auto_wait()
    
    # Save the database to ensure subsequent steps (like export) use the analyzed data
    # 0 means save to the default IDB file
    idc.save_database(0)
    
    # Get the marker file path from environment variable
    marker_path = os.environ.get("IDA_ANALYSIS_MARKER")
    if marker_path:
        with open(marker_path, "w") as f:
            f.write("done")

if __name__ == "__main__":
    main()
