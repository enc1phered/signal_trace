import argparse
import json
import pandas as pd

# Add command line arguments
parser = argparse.ArgumentParser()
parser.add_argument("-p", "--Platform", help = "Use -p or --Platform to supply the platform (Windows, Linux, MacOS)")
args = parser.parse_args()

# Variables
parsed_techniques = {}
parsed_output = []
output_json = "output/attack_tables.json"

# Load attack techniques model (https://github.com/OTRF/OSSEM-DM/blob/main/use-cases/mitre_attack/techniques_to_events_mapping.json)
techniques_model_path = "source/techniques_to_events_mapping.json"
with open(techniques_model_path, "r") as f:
    techniques_model = json.load(f)

# parse data of interest
for technique in techniques_model:
    #if technique["log_source"] == "Microsoft Defender for Endpoint":
        parsed_techniques = {
            "tactic": technique["tactic"],
            "technique_id": technique["technique_id"],
            "technique_name" : technique["technique"],
            "event_description" : technique["name"],
            "platform": technique["platform"], 
            "table_name_or_event_id": technique["event_id"], 
            "log_source": technique["log_source"],
            "filter": technique["filter_in"]
            }
        parsed_output.append(parsed_techniques)

with open(output_json, "w") as f:
    json.dump(parsed_output, f, indent=2)

df = pd.read_json(output_json)

#df = df.explode(("tactic"))
#df = df.explode(("platform"))
df["tactic"] = df["tactic"].apply(
    lambda x: ", ".join(x)
)

df["platform"] = df["platform"].apply(
    lambda x: ", ".join(x)
)

html = df.to_html(classes="display stripe hover cell-border order-column", table_id="jsonTable", index=False)

# Write HTML page
with open("table.html", "w") as f:
    f.write(f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Log Source Lookup</title>
            
    <link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/jquery.dataTables.min.css">
            
    <script src="https://code.jquery.com/jquery-3.7.0.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
            
    <style>
    /* Modern Font and Background */
    body {{
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        background-color: #f4f6f9;
        margin: 0;
        padding: 20px;
        color: #333;
    }}

    h1 {{
        text-align: center;
        color: #2c3e50;
        margin-bottom: 30px;
    }}
    
    /* Table Container Styling */
    #jsonTable_wrapper {{
        background-color: #ffffff;
        padding: 20px;
        border-radius: 8px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }}

    /* Header Styling */
    table.dataTable thead th {{
        background-color: #34495e;
        color: white;
        font-weight: 600;
        padding: 12px 10px;
    }}
    
    /* Footer/Filter Styling */
    tfoot {{
        display: table-header-group; /* Moves filters to top if you prefer, remove this line to keep at bottom */
    }}
    
    tfoot th {{
        padding: 5px;
    }}

    tfoot select {{
        width: 100%;
        padding: 8px;
        border: 1px solid #ddd;
        border-radius: 4px;
        background-color: #f9f9f9;
        font-family: inherit;
    }}
    
    /* Row Styling Override */
    table.dataTable tbody tr:hover {{
        background-color: #f1f1f1 !important;
    }}
    </style>
            
</head>
<body>

<h1>Log Source Lookup</h1>            

{html}

<script>
$(document).ready(function () {{
    // Setup - add a text input to each footer cell
    $('#jsonTable tfoot th').each(function () {{
        var title = $(this).text();
        $(this).html('<input type="text" placeholder="Search ' + title + '" />');
    }});

    var table = $('#jsonTable').DataTable({{
        paging: true,
        searching: true,
        ordering: true,
        pageLength: 25,
        autoWidth: false, // Helps with responsiveness
        order: [],
        initComplete: function () {{
            var api = this.api();

            // Create a dropdown filter for each column
            api.columns().every(function () {{
                var column = this;

                // Append the filter to the footer
                var footer = $('<th></th>').appendTo(
                    $('#jsonTable tfoot').length
                        ? $('#jsonTable tfoot tr')
                        : $('<tfoot><tr></tr></tfoot>').appendTo('#jsonTable').find('tr')
                );
                
                // Clear any existing content (like the placeholder text created by to_html)
                footer.empty(); 

                var select = $('<select><option value="">All</option></select>')
                    .appendTo(footer)
                    .on('change', function () {{
                        var val = $.fn.dataTable.util.escapeRegex($(this).val());

                        if (val == "") {{
                            column.search("").draw();
                        }}
                        else {{
                            // The regex fix we applied earlier
                            column.search('(^|,)\\\\s*' + val + '\\\\s*(,|$)', true, false).draw();
                        }}
                    }});

                let uniqueValues = new Set();

                column.data().each(function (d) {{
                    if (!d) return;
                    // Split by comma if the cell has multiple values
                    d.split(',').forEach(function (item) {{
                        // Clean up the item (remove whitespace)
                        let cleanItem = item.trim();
                        // Ignore empty strings that might result from trailing commas
                        if (cleanItem) uniqueValues.add(cleanItem);
                    }});
                }});

                Array.from(uniqueValues).sort().forEach(function (val) {{
                    select.append('<option value="' + val + '">' + val + '</option>');
                }});
            }});
        }}
    }});
}});
</script>
</body>
</html>
""")

