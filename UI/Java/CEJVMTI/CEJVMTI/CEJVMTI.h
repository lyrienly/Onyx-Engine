#ifdef CEJVMTI_EXPORTS
#define CEJVMTI_API __declspec(dllexport)
#else
#define CEJVMTI_API __declspec(dllimport)
#endif

class CEJVMTI_API CCEJVMTI {
public:
	CCEJVMTI(void);

};

extern CEJVMTI_API int nCEJVMTI;

CEJVMTI_API int fnCEJVMTI(void);
