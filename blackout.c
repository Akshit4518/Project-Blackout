
#include <stdio.h>
#include <string.h>

struct Log
{
    int time;
    char username[20];
    char event[30];
    char ip[20];
};

struct User
{
    char name[20];
    char role[20];
    char access[20];
};

struct Log logs[20];

struct User users[4] = {
    {"USER01", "Employee", "Standard"},
    {"USER02", "Employee", "Standard"},
    {"USER03", "Employee", "Admin"},
    {"USER04", "Manager", "Standard"}
};

char evidence[10][100];

int log_count = 0;
int evidence_count = 0;
int score = 0;

void create_file()
{
    FILE *fp;

    fp = fopen("logs.txt", "r");

    if (fp != NULL)
    {
        fclose(fp);
        return;
    }

    fp = fopen("logs.txt", "w");

    if (fp == NULL)
    {
        printf("File creation failed.\n");
        return;
    }

    fprintf(fp, "830 USER01 LOGIN_SUCCESS 192.168.1.10\n");
    fprintf(fp, "835 USER02 LOGIN_SUCCESS 192.168.1.12\n");
    fprintf(fp, "842 USER03 LOGIN_FAILED 192.168.1.15\n");
    fprintf(fp, "843 USER03 LOGIN_FAILED 192.168.1.15\n");
    fprintf(fp, "844 USER03 LOGIN_FAILED 192.168.1.15\n");
    fprintf(fp, "845 USER03 LOGIN_SUCCESS 192.168.1.15\n");
    fprintf(fp, "855 USER03 PERMISSION_CHANGE 192.168.1.15\n");
    fprintf(fp, "857 SYSTEM CONFIG_CHANGE NONE\n");
    fprintf(fp, "900 SERVER SYSTEM_FAILURE NONE\n");

    fclose(fp);
}

void load_logs()
{
    FILE *fp;

    fp = fopen("logs.txt", "r");

    if (fp == NULL)
    {
        printf("Unable to open file.\n");
        return;
    }

    log_count = 0;

    while (log_count < 20 &&
           fscanf(fp, "%d %19s %29s %19s",
           &logs[log_count].time,
           logs[log_count].username,
           logs[log_count].event,
           logs[log_count].ip) == 4)
    {
        log_count++;
    }

    fclose(fp);
}

void display_logs()
{
    int i;

    printf("\nSYSTEM LOGS\n");

    for (i = 0; i < log_count; i++)
    {
        printf("%04d | %s | %s | %s\n",
        logs[i].time,
        logs[i].username,
        logs[i].event,
        logs[i].ip);
    }
}

void analyse_login()
{
    int i, j;
    int failed;
    int found = 0;

    printf("\nLOGIN ANALYSIS\n");

    for (i = 0; i < log_count; i++)
    {
        if (strcmp(logs[i].event, "LOGIN_FAILED") == 0)
        {
            failed = 0;

            for (j = 0; j < log_count; j++)
            {
                if (strcmp(logs[i].username,
                           logs[j].username) == 0 &&
                    strcmp(logs[j].event,
                           "LOGIN_FAILED") == 0)
                {
                    failed++;
                }
            }

            if (failed >= 3)
            {
                printf("Suspicious user: %s\n",
                       logs[i].username);

                found = 1;
                break;
            }
        }
    }

    if (found)
    {
        printf("Multiple failed login attempts detected.\n");

        strcpy(evidence[evidence_count],
        "Multiple failed login attempts detected.");

        evidence_count++;
        score += 10;
    }
    else
    {
        printf("No suspicious activity found.\n");
    }
}

void check_access()
{
    int i;
    int found = 0;

    printf("\nACCESS CONTROL ANALYSIS\n");

    for (i = 0; i < 4; i++)
    {
        printf("\nUser: %s", users[i].name);
        printf("\nRole: %s", users[i].role);
        printf("\nAccess: %s\n", users[i].access);

        if (strcmp(users[i].role, "Employee") == 0 &&
            strcmp(users[i].access, "Admin") == 0)
        {
            printf("Access violation detected.\n");

            found = 1;
        }
    }

    if (found)
    {
        strcpy(evidence[evidence_count],
        "Employee account has administrator access.");

        evidence_count++;
        score += 10;
    }
}

void timeline()
{
    int i, j;
    struct Log temp;

    for (i = 0; i < log_count - 1; i++)
    {
        for (j = 0; j < log_count - i - 1; j++)
        {
            if (logs[j].time > logs[j + 1].time)
            {
                temp = logs[j];
                logs[j] = logs[j + 1];
                logs[j + 1] = temp;
            }
        }
    }

    printf("\nINCIDENT TIMELINE\n");

    for (i = 0; i < log_count; i++)
    {
        printf("%04d | %s | %s\n",
        logs[i].time,
        logs[i].username,
        logs[i].event);
    }

    strcpy(evidence[evidence_count],
    "Incident timeline reconstructed.");

    evidence_count++;
    score += 10;
}

void display_evidence()
{
    int i;

    printf("\nCOLLECTED EVIDENCE\n");

    if (evidence_count == 0)
    {
        printf("No evidence collected.\n");
        return;
    }

    for (i = 0; i < evidence_count; i++)
    {
        printf("%d. %s\n", i + 1, evidence[i]);
    }
}

void final_report()
{
    int choice;

    printf("\nFINAL INVESTIGATION REPORT\n");

    display_evidence();

    printf("\nPossible causes:\n");
    printf("1. Unauthorized account activity\n");
    printf("2. Configuration error\n");
    printf("3. Hardware failure\n");

    printf("\nEnter your conclusion: ");
    scanf("%d", &choice);

    if (choice == 1)
    {
        printf("\nInvestigation conclusion accepted.\n");
        score += 20;
    }
    else
    {
        printf("\nIncorrect conclusion.\n");
    }

    printf("\nTotal evidence: %d", evidence_count);
    printf("\nFinal score: %d\n", score);
}

void save_report()
{
    FILE *fp;
    int i;

    fp = fopen("report.txt", "w");

    if (fp == NULL)
    {
        printf("Unable to save report.\n");
        return;
    }

    fprintf(fp, "PROJECT BLACKOUT\n");
    fprintf(fp, "INVESTIGATION REPORT\n\n");

    for (i = 0; i < evidence_count; i++)
    {
        fprintf(fp, "%d. %s\n", i + 1, evidence[i]);
    }

    fprintf(fp, "\nTotal Evidence: %d", evidence_count);
    fprintf(fp, "\nFinal Score: %d", score);

    fclose(fp);

    printf("\nReport saved successfully.\n");
}

int main()
{
    int choice;

    create_file();
    load_logs();

    if (log_count == 0)
    {
        printf("No log records available.\n");
        return 1;
    }

    printf("\n==============================\n");
    printf("       PROJECT BLACKOUT\n");
    printf("    SECURITY INVESTIGATION\n");
    printf("==============================\n");

    do
    {
        printf("\n1. View system logs");
        printf("\n2. Analyse login activity");
        printf("\n3. Check access permissions");
        printf("\n4. Reconstruct timeline");
        printf("\n5. View collected evidence");
        printf("\n6. Final investigation report");
        printf("\n7. Save report");
        printf("\n8. Exit");

        printf("\n\nEnter your choice: ");
        scanf("%d", &choice);

        switch (choice)
        {
            case 1:
                display_logs();
                break;

            case 2:
                analyse_login();
                break;

            case 3:
                check_access();
                break;

            case 4:
                timeline();
                break;

            case 5:
                display_evidence();
                break;

            case 6:
                final_report();
                break;

            case 7:
                save_report();
                break;

            case 8:
                printf("\nExiting Project Blackout.\n");
                break;

            default:
                printf("\nInvalid choice.\n");
        }

    } while (choice != 8);

    return 0;
}
