#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>

#pragma comment(lib, "bcrypt.lib")

#define BUFFER_SIZE 4096

/*
 * 파일의 SHA-256 해시값을 계산하는 함수
 *
 * fileName  : 검사할 파일 이름
 * hashValue : 계산된 SHA-256 값을 저장할 배열
 *
 * 성공하면 1, 실패하면 0 반환
 */
int calculateSHA256(const char *fileName, unsigned char hashValue[32])
{
    HANDLE hFile = INVALID_HANDLE_VALUE;
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status;
    DWORD hashObjectSize = 0;
    DWORD dataSize = 0;
    unsigned char *hashObject = NULL;
    BYTE buffer[BUFFER_SIZE];
    DWORD readBytes;

    /*
     * -------------------------------------------------
     * 1. 검사할 파일 열기
     * -------------------------------------------------
     * GENERIC_READ를 사용하므로 파일을 읽기 전용으로 접근한다.
     */
    hFile = CreateFileA(fileName, GENERIC_READ, FILE_SHARE_READ,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("파일 열기 실패 : %s\n", fileName);
        printf("Error Code : %lu\n", GetLastError());
        return 0;
    }

    /*
     * -------------------------------------------------
     * 2. SHA-256 알고리즘 공급자 열기
     * -------------------------------------------------
     */
    status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0);

    if (status != 0)
    {
        printf("BCryptOpenAlgorithmProvider 실패\n");
        CloseHandle(hFile);
        return 0;
    }

    /*
     * -------------------------------------------------
     * 3. SHA-256 해시 객체 크기 확인
     * -------------------------------------------------
     */
    status = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH,
                               (PUCHAR)&hashObjectSize, sizeof(DWORD), &dataSize, 0);

    if (status != 0)
    {
        printf("BCryptGetProperty 실패\n");
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        CloseHandle(hFile);
        return 0;
    }

    /*
     * -------------------------------------------------
     * 4. 해시 객체를 저장할 메모리 할당
     * -------------------------------------------------
     */
    hashObject = (unsigned char *)HeapAlloc(GetProcessHeap(), 0, hashObjectSize);

    if (hashObject == NULL)
    {
        printf("메모리 할당 실패\n");
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        CloseHandle(hFile);
        return 0;
    }

    /*
     * -------------------------------------------------
     * 5. SHA-256 Hash 객체 생성
     * -------------------------------------------------
     */
    status = BCryptCreateHash(hAlgorithm, &hHash, hashObject,
                              hashObjectSize, NULL, 0, 0);

    if (status != 0)
    {
        printf("BCryptCreateHash 실패\n");
        HeapFree(GetProcessHeap(), 0, hashObject);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        CloseHandle(hFile);
        return 0;
    }

    /*
     * -------------------------------------------------
     * 6. 파일 내용을 일정 크기로 반복해서 읽는다.
     * -------------------------------------------------
     * 전체 파일을 한 번에 메모리에 올리지 않고 4096 Byte 단위로 읽는다.
     */
    while (1)
    {
        if (!ReadFile(hFile, buffer, BUFFER_SIZE, &readBytes, NULL))
        {
            printf("파일 읽기 실패\n");
            BCryptDestroyHash(hHash);
            HeapFree(GetProcessHeap(), 0, hashObject);
            BCryptCloseAlgorithmProvider(hAlgorithm, 0);
            CloseHandle(hFile);
            return 0;
        }

        /* 파일 끝에 도달 */
        if (readBytes == 0)
        {
            break;
        }

        /* 읽은 데이터를 SHA-256 계산에 추가 */
        status = BCryptHashData(hHash, buffer, readBytes, 0);

        if (status != 0)
        {
            printf("BCryptHashData 실패\n");
            BCryptDestroyHash(hHash);
            HeapFree(GetProcessHeap(), 0, hashObject);
            BCryptCloseAlgorithmProvider(hAlgorithm, 0);
            CloseHandle(hFile);
            return 0;
        }
    }

    /*
     * -------------------------------------------------
     * 7. 최종 SHA-256 해시값 생성
     * -------------------------------------------------
     * SHA-256 결과는 32 Byte이다.
     */
    status = BCryptFinishHash(hHash, hashValue, 32, 0);

    if (status != 0)
    {
        printf("BCryptFinishHash 실패\n");
        BCryptDestroyHash(hHash);
        HeapFree(GetProcessHeap(), 0, hashObject);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        CloseHandle(hFile);
        return 0;
    }

    /* 사용한 자원 반환 */
    BCryptDestroyHash(hHash);
    HeapFree(GetProcessHeap(), 0, hashObject);
    BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    CloseHandle(hFile);

    return 1;
}

/* SHA-256 해시값 출력 */
void printHash(const unsigned char hash[32])
{
    int i;

    for (i = 0; i < 32; i++)
    {
        printf("%02x", hash[i]);
    }

    printf("\n");
}

/* 두 SHA-256 해시값 비교 */
int compareHash(const unsigned char hash1[32], const unsigned char hash2[32])
{
    int i;

    for (i = 0; i < 32; i++)
    {
        if (hash1[i] != hash2[i])
        {
            return 0;
        }
    }

    return 1;
}

/*
 * -------------------------------------------------
 * main
 * -------------------------------------------------
 */
int main(void)
{
    char originalFile[MAX_PATH];
    char evidenceFile[MAX_PATH];
    unsigned char originalHash[32];
    unsigned char evidenceHash[32];

    /* Windows Console UTF-8 출력 */
    SetConsoleOutputCP(CP_UTF8);

    printf("=========================================\n");
    printf(" Digital Forensic File Integrity Check\n");
    printf(" SHA-256 File Hash Verification\n");
    printf("=========================================\n\n");

    /* 원본 파일 입력 */
    printf("원본 파일 경로 입력 : ");
    scanf_s("%259s", originalFile, (unsigned)sizeof(originalFile));

    /* 증거 또는 복사 파일 입력 */
    printf("비교 파일 경로 입력 : ");
    scanf_s("%259s", evidenceFile, (unsigned)sizeof(evidenceFile));
    printf("\n");

    /* 원본 파일의 SHA-256 계산 */
    if (!calculateSHA256(originalFile, originalHash))
    {
        return 1;
    }

    /* 비교 파일의 SHA-256 계산 */
    if (!calculateSHA256(evidenceFile, evidenceHash))
    {
        return 1;
    }

    printf("-----------------------------------------\n");
    printf("[원본 파일]\n");
    printf("파일 : %s\n", originalFile);
    printf("SHA-256 : ");
    printHash(originalHash);

    printf("\n");
    printf("[비교 파일]\n");
    printf("파일 : %s\n", evidenceFile);
    printf("SHA-256 : ");
    printHash(evidenceHash);
    printf("\n-----------------------------------------\n");

    /* 두 파일의 해시값 비교 */
    if (compareHash(originalHash, evidenceHash))
    {
        printf("[검증 결과]\n");
        printf("SHA-256 값이 같습니다.\n");
        printf("파일의 무결성이 유지되었습니다.\n");
    }
    else
    {
        printf("[검증 결과]\n");
        printf("SHA-256 값이 다릅니다.\n");
        printf("파일 내용이 변경되었을 가능성이 있습니다.\n");
    }

    printf("-----------------------------------------\n");
    return 0;
}
