
#ifndef LVM_SETEXTENDEDLISTVIEWSTYLE
	#define LVM_SETEXTENDEDLISTVIEWSTYLE 0x1036
#endif
#ifndef LVS_EX_ONECLICKACTIVATE
	#define LVS_EX_ONECLICKACTIVATE 0x40
#endif
#ifndef LVS_EX_FULLROWSELECT
	#define LVS_EX_FULLROWSELECT 0x20
#endif

#ifndef LVS_EX_CHECKBOXES
	#define LVS_EX_CHECKBOXES 4
#endif

#define DLG_TIME_UNIT_SECONDS 1
#define DLG_TIME_UNIT_MINUTES 2
#define DLG_TIME_UNIT_HOURS 3
#define DLG_TIME_UNIT_DAYS 4
#define DLG_TIME_UNIT_WEEKS 5
#define DLG_TIME_UNIT_MONTHS 6
#define DLG_TIME_UNIT_YEARS 7

#pragma pack(push,1)
typedef struct lang_dlg_info
{	int ctrlId;
	int langId;
} lang_dlg_info;
#pragma pack(pop)

HWND createChildDialog(HANDLE hParent,int resourceId,DLGPROC dialogFunc);
void getEditData(HWND hDlg,int editBox,config_line_t **option,const char *value);
void setEditData(HWND hDlg,int editBox,config_line_t *option);
void changeDialogStrings(HWND hDlg,lang_dlg_info *dlgInfo);
void getEditData1(HWND hDlg,int editBox,config_line_t **option,const char *value);
void selectComboId(HWND hDlg,int combo,LPARAM id);
int dlgDebug_find_address(char *str);
void dlgDebug_copy_address(char *str,char *dest,int max);
int dlgDebug_find_domain(char *str);
void dlgUtil_hideAll(void);
void dlgUtil_restoreAll(void);
void initmemunits(HWND hDlg,int combo);
void inittimeunits(HWND hDlg,int combo,int edit,uint32_t value);
uint32_t gettimeunit(HWND hDlg,int combo,int edit);
