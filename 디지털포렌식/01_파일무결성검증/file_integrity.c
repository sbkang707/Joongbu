/*
 * =====================================================================
 *  file_integrity.c  —  [디지털 포렌식] Windows 기반 파일 무결성 검증
 * =====================================================================
 *  원본 파일과 증거(복사) 파일의 SHA-256 해시값을 각각 계산하여 비교한다.
 *    - 두 해시값이 같으면  → 파일 무결성 유지
 *    - 두 해시값이 다르면  → 파일 내용이 변경되었을 가능성
 *
 *  사용 API : Windows CNG(Cryptography API: Next Generation)의 BCrypt 함수
 *  컴파일   : cl /W4 /utf-8 file_integrity.c            (Developer Command Prompt)
 *  주의     : 이 파일은 UTF-8로 저장되어 있으므로 /utf-8 옵션을 반드시 붙인다.
 *
 *  ※ 원본 코드(원본자료/Windows_SHA256_File_Integrity_Check.c)와 실행 로직은
 *    완전히 동일하며, 학습용으로 라인별 주석만 추가하였다.
 * =====================================================================
 */

#define WIN32_LEAN_AND_MEAN        // windows.h에서 잘 쓰지 않는 헤더(소켓, OLE 등)를 제외해 컴파일 속도를 높인다

#include <windows.h>               // CreateFileA, ReadFile, CloseHandle, HeapAlloc 등 Windows 기본 API 선언
#include <bcrypt.h>                // BCryptOpenAlgorithmProvider 등 CNG 암호화(해시) API 선언
#include <stdio.h>                 // printf, scanf_s 등 표준 입출력 함수 선언

#pragma comment(lib, "bcrypt.lib") // 링커에게 bcrypt.lib를 자동으로 링크하라고 지시 (명령줄에 lib 생략 가능)

#define BUFFER_SIZE 4096           // 파일을 한 번에 읽어 들일 크기: 4096바이트(4KB, 일반적인 디스크 페이지 크기)

/*
 * 파일의 SHA-256 해시값을 계산하는 함수
 *
 * fileName  : 검사할 파일 이름
 * hashValue : 계산된 SHA-256 값을 저장할 배열
 *
 * 성공하면 1, 실패하면 0 반환
 */
int calculateSHA256(const char *fileName, unsigned char hashValue[32]) // SHA-256 결과는 256비트 = 32바이트
{                                                   // 함수 본문 시작
    HANDLE hFile = INVALID_HANDLE_VALUE;            // 열린 파일을 가리킬 핸들 (초기값: '유효하지 않음')
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;            // SHA-256 알고리즘 공급자 핸들
    BCRYPT_HASH_HANDLE hHash = NULL;                // 실제 해시 계산을 수행할 해시 객체 핸들
    NTSTATUS status;                                // BCrypt 함수의 반환 상태값 (0 = STATUS_SUCCESS = 성공)
    DWORD hashObjectSize = 0;                       // 해시 객체가 내부적으로 필요로 하는 메모리 크기(바이트)
    DWORD dataSize = 0;                             // BCryptGetProperty가 실제로 기록한 바이트 수
    unsigned char *hashObject = NULL;               // 해시 객체용으로 동적 할당할 메모리의 시작 주소
    BYTE buffer[BUFFER_SIZE];                       // 파일에서 읽은 데이터를 잠시 담아 둘 4KB 버퍼
    DWORD readBytes;                                // ReadFile이 실제로 읽은 바이트 수

    /*
     * -------------------------------------------------
     * 1. 검사할 파일 열기
     * -------------------------------------------------
     * GENERIC_READ를 사용하므로 파일을 읽기 전용으로 접근한다.
     */
    hFile = CreateFileA(fileName,                   // 열 파일 경로 (A = ANSI 문자열 버전)
                        GENERIC_READ,               // 읽기 권한만 요청 → 증거 파일을 실수로 수정하지 않음(포렌식 원칙)
                        FILE_SHARE_READ,            // 다른 프로세스의 '읽기'는 허용, 쓰기/삭제는 차단
                        NULL,                       // 보안 속성: 기본값 사용
                        OPEN_EXISTING,              // 파일이 이미 존재할 때만 열기 (없으면 새로 만들지 않고 실패)
                        FILE_ATTRIBUTE_NORMAL,      // 특별한 속성 없이 일반 파일로 처리
                        NULL);                      // 템플릿 파일: 사용하지 않음

    if (hFile == INVALID_HANDLE_VALUE)              // 파일 열기에 실패했는지 검사
    {                                               // 실패 처리 블록 시작
        printf("파일 열기 실패 : %s\n", fileName);  // 어떤 파일이 열리지 않았는지 출력
        printf("Error Code : %lu\n", GetLastError()); // 원인 코드 출력 (2 = 파일 없음, 3 = 경로 없음, 5 = 접근 거부, 32 = 다른 프로세스가 사용 중)
        return 0;                                   // 실패(0) 반환
    }                                               // 실패 처리 블록 끝

    /*
     * -------------------------------------------------
     * 2. SHA-256 알고리즘 공급자 열기
     * -------------------------------------------------
     */
    status = BCryptOpenAlgorithmProvider(&hAlgorithm,             // [출력] 알고리즘 핸들을 받을 변수
                                         BCRYPT_SHA256_ALGORITHM, // 사용할 알고리즘: L"SHA256"
                                         NULL,                    // 공급자: NULL이면 Windows 기본 공급자
                                         0);                      // 플래그: 없음 (HMAC 등을 쓸 때만 지정)

    if (status != 0)                                // 0(STATUS_SUCCESS)이 아니면 실패
    {                                               // 실패 처리 블록 시작
        printf("BCryptOpenAlgorithmProvider 실패\n"); // 오류 메시지 출력
        CloseHandle(hFile);                         // 앞 단계에서 연 파일 핸들 반환
        return 0;                                   // 실패(0) 반환
    }                                               // 실패 처리 블록 끝

    /*
     * -------------------------------------------------
     * 3. SHA-256 해시 객체 크기 확인
     * -------------------------------------------------
     */
    status = BCryptGetProperty(hAlgorithm,              // 조회할 알고리즘 핸들
                               BCRYPT_OBJECT_LENGTH,    // 조회 항목: 해시 객체에 필요한 메모리 크기
                               (PUCHAR)&hashObjectSize, // [출력] 결과를 저장할 변수 주소 (바이트 포인터로 형변환)
                               sizeof(DWORD),           // 출력 버퍼 크기 (DWORD = 4바이트)
                               &dataSize,               // [출력] 실제로 기록된 바이트 수
                               0);                      // 플래그: 없음

    if (status != 0)                                // 속성 조회 실패 여부 검사
    {                                               // 실패 처리 블록 시작
        printf("BCryptGetProperty 실패\n");         // 오류 메시지 출력
        BCryptCloseAlgorithmProvider(hAlgorithm, 0); // 2단계에서 연 알고리즘 공급자 반환
        CloseHandle(hFile);                         // 1단계에서 연 파일 핸들 반환
        return 0;                                   // 실패(0) 반환
    }                                               // 실패 처리 블록 끝

    /*
     * -------------------------------------------------
     * 4. 해시 객체를 저장할 메모리 할당
     * -------------------------------------------------
     */
    hashObject = (unsigned char *)HeapAlloc(GetProcessHeap(), // 현재 프로세스의 기본 힙에서
                                            0,                // 플래그 없음 (0으로 초기화하지 않음)
                                            hashObjectSize);  // 3단계에서 알아낸 크기만큼 메모리 할당

    if (hashObject == NULL)                         // 메모리 할당 실패 여부 검사
    {                                               // 실패 처리 블록 시작
        printf("메모리 할당 실패\n");               // 오류 메시지 출력
        BCryptCloseAlgorithmProvider(hAlgorithm, 0); // 알고리즘 공급자 반환
        CloseHandle(hFile);                         // 파일 핸들 반환
        return 0;                                   // 실패(0) 반환
    }                                               // 실패 처리 블록 끝

    /*
     * -------------------------------------------------
     * 5. SHA-256 Hash 객체 생성
     * -------------------------------------------------
     */
    status = BCryptCreateHash(hAlgorithm,           // 사용할 알고리즘(SHA-256) 핸들
                              &hHash,               // [출력] 생성된 해시 객체 핸들
                              hashObject,           // 해시 객체가 내부 상태를 저장할 메모리(4단계에서 할당)
                              hashObjectSize,       // 위 메모리의 크기
                              NULL,                 // 비밀 키: NULL (HMAC이 아닌 일반 해시이므로 키 없음)
                              0,                    // 비밀 키 길이: 0
                              0);                   // 플래그: 없음

    if (status != 0)                                // 해시 객체 생성 실패 여부 검사
    {                                               // 실패 처리 블록 시작
        printf("BCryptCreateHash 실패\n");          // 오류 메시지 출력
        HeapFree(GetProcessHeap(), 0, hashObject);  // 4단계에서 할당한 메모리 해제
        BCryptCloseAlgorithmProvider(hAlgorithm, 0); // 알고리즘 공급자 반환
        CloseHandle(hFile);                         // 파일 핸들 반환
        return 0;                                   // 실패(0) 반환
    }                                               // 실패 처리 블록 끝

    /*
     * -------------------------------------------------
     * 6. 파일 내용을 일정 크기로 반복해서 읽는다.
     * -------------------------------------------------
     * 전체 파일을 한 번에 메모리에 올리지 않고 4096 Byte 단위로 읽는다.
     * → 수 GB 크기의 디스크 이미지도 4KB 메모리만으로 해시를 계산할 수 있다.
     */
    while (1)                                       // 파일 끝(EOF)에 도달할 때까지 무한 반복
    {                                               // 반복문 시작
        if (!ReadFile(hFile, buffer, BUFFER_SIZE, &readBytes, NULL)) // 최대 4096바이트를 buffer로 읽기, 실패 시 FALSE
        {                                           // 읽기 실패 처리 블록 시작
            printf("파일 읽기 실패\n");             // 오류 메시지 출력
            BCryptDestroyHash(hHash);               // 5단계에서 만든 해시 객체 파괴
            HeapFree(GetProcessHeap(), 0, hashObject); // 해시 객체 메모리 해제
            BCryptCloseAlgorithmProvider(hAlgorithm, 0); // 알고리즘 공급자 반환
            CloseHandle(hFile);                     // 파일 핸들 반환
            return 0;                               // 실패(0) 반환
        }                                           // 읽기 실패 처리 블록 끝

        /* 파일 끝에 도달 */
        if (readBytes == 0)                         // ReadFile이 성공했는데 0바이트를 읽었다면 = 파일 끝(EOF)
        {                                           // EOF 처리 블록 시작
            break;                                  // 반복문 탈출 → 7단계로 이동
        }                                           // EOF 처리 블록 끝

        /* 읽은 데이터를 SHA-256 계산에 추가 */
        status = BCryptHashData(hHash, buffer, readBytes, 0); // 방금 읽은 readBytes만큼(마지막 조각은 4096보다 작을 수 있음) 해시에 누적

        if (status != 0)                            // 해시 누적 실패 여부 검사
        {                                           // 실패 처리 블록 시작
            printf("BCryptHashData 실패\n");        // 오류 메시지 출력
            BCryptDestroyHash(hHash);               // 해시 객체 파괴
            HeapFree(GetProcessHeap(), 0, hashObject); // 해시 객체 메모리 해제
            BCryptCloseAlgorithmProvider(hAlgorithm, 0); // 알고리즘 공급자 반환
            CloseHandle(hFile);                     // 파일 핸들 반환
            return 0;                               // 실패(0) 반환
        }                                           // 실패 처리 블록 끝
    }                                               // 반복문 끝

    /*
     * -------------------------------------------------
     * 7. 최종 SHA-256 해시값 생성
     * -------------------------------------------------
     * SHA-256 결과는 32 Byte이다.
     */
    status = BCryptFinishHash(hHash, hashValue, 32, 0); // 누적된 데이터로 최종 해시를 확정하여 hashValue(32바이트)에 저장

    if (status != 0)                                // 최종 해시 생성 실패 여부 검사
    {                                               // 실패 처리 블록 시작
        printf("BCryptFinishHash 실패\n");          // 오류 메시지 출력
        BCryptDestroyHash(hHash);                   // 해시 객체 파괴
        HeapFree(GetProcessHeap(), 0, hashObject);  // 해시 객체 메모리 해제
        BCryptCloseAlgorithmProvider(hAlgorithm, 0); // 알고리즘 공급자 반환
        CloseHandle(hFile);                         // 파일 핸들 반환
        return 0;                                   // 실패(0) 반환
    }                                               // 실패 처리 블록 끝

    /* 사용한 자원 반환 (획득한 순서의 역순으로 정리) */
    BCryptDestroyHash(hHash);                       // 5단계: 해시 객체 파괴
    HeapFree(GetProcessHeap(), 0, hashObject);      // 4단계: 해시 객체 메모리 해제
    BCryptCloseAlgorithmProvider(hAlgorithm, 0);    // 2단계: 알고리즘 공급자 반환
    CloseHandle(hFile);                             // 1단계: 파일 핸들 반환

    return 1;                                       // 성공(1) 반환 — 결과는 hashValue 배열에 들어 있음
}                                                   // calculateSHA256 함수 끝

/* SHA-256 해시값 출력 */
void printHash(const unsigned char hash[32])        // 32바이트 해시값을 16진수 문자열로 출력하는 함수
{                                                   // 함수 본문 시작
    int i;                                          // 반복문 인덱스

    for (i = 0; i < 32; i++)                        // 32바이트를 처음부터 끝까지 순회
    {                                               // 반복문 시작
        printf("%02x", hash[i]);                    // 1바이트를 2자리 소문자 16진수로 출력 (예: 0x0a → "0a")
    }                                               // 반복문 끝 → 총 64글자의 16진수 문자열이 출력됨

    printf("\n");                                   // 줄바꿈
}                                                   // printHash 함수 끝

/* 두 SHA-256 해시값 비교 */
int compareHash(const unsigned char hash1[32], const unsigned char hash2[32]) // 같으면 1, 다르면 0 반환
{                                                   // 함수 본문 시작
    int i;                                          // 반복문 인덱스

    for (i = 0; i < 32; i++)                        // 32바이트를 한 바이트씩 비교
    {                                               // 반복문 시작
        if (hash1[i] != hash2[i])                   // 한 바이트라도 다르면
        {                                           // 불일치 블록 시작
            return 0;                               // 즉시 '다름(0)' 반환
        }                                           // 불일치 블록 끝
    }                                               // 반복문 끝

    return 1;                                       // 32바이트가 모두 같으면 '같음(1)' 반환
}                                                   // compareHash 함수 끝

/*
 * -------------------------------------------------
 * main
 * -------------------------------------------------
 */
int main(void)                                      // 프로그램 시작 지점
{                                                   // main 함수 본문 시작
    char originalFile[MAX_PATH];                    // 원본 파일 경로를 저장할 배열 (MAX_PATH = 260)
    char evidenceFile[MAX_PATH];                    // 비교(증거) 파일 경로를 저장할 배열
    unsigned char originalHash[32];                 // 원본 파일의 SHA-256 결과(32바이트)
    unsigned char evidenceHash[32];                 // 비교 파일의 SHA-256 결과(32바이트)

    /* Windows Console UTF-8 출력 */
    SetConsoleOutputCP(CP_UTF8);                    // 콘솔 출력 코드페이지를 UTF-8(65001)로 바꿔 한글이 깨지지 않게 함

    printf("=========================================\n"); // 제목 테두리 출력
    printf(" Digital Forensic File Integrity Check\n");    // 프로그램 제목 출력
    printf(" SHA-256 File Hash Verification\n");           // 부제목 출력
    printf("=========================================\n\n"); // 제목 테두리 + 빈 줄 출력

    /* 원본 파일 입력 */
    printf("원본 파일 경로 입력 : ");               // 원본 파일 경로 입력 안내
    scanf_s("%259s", originalFile, (unsigned)sizeof(originalFile)); // 최대 259글자(+NULL 1 = 260) 입력, 공백 전까지만 읽음

    /* 증거 또는 복사 파일 입력 */
    printf("비교 파일 경로 입력 : ");               // 비교 파일 경로 입력 안내
    scanf_s("%259s", evidenceFile, (unsigned)sizeof(evidenceFile)); // 버퍼 크기를 함께 넘겨 오버플로를 방지하는 안전한 입력
    printf("\n");                                   // 빈 줄 출력

    /* 원본 파일의 SHA-256 계산 */
    if (!calculateSHA256(originalFile, originalHash)) // 원본 파일 해시 계산, 실패(0)하면
    {                                               // 실패 처리 블록 시작
        return 1;                                   // 오류 종료 코드 1로 프로그램 종료
    }                                               // 실패 처리 블록 끝

    /* 비교 파일의 SHA-256 계산 */
    if (!calculateSHA256(evidenceFile, evidenceHash)) // 비교 파일 해시 계산, 실패(0)하면
    {                                               // 실패 처리 블록 시작
        return 1;                                   // 오류 종료 코드 1로 프로그램 종료
    }                                               // 실패 처리 블록 끝

    printf("-----------------------------------------\n"); // 구분선 출력
    printf("[원본 파일]\n");                        // 원본 파일 섹션 제목
    printf("파일 : %s\n", originalFile);            // 원본 파일 경로 출력
    printf("SHA-256 : ");                           // 해시 출력 앞 머리말
    printHash(originalHash);                        // 원본 파일 해시를 64자리 16진수로 출력

    printf("\n");                                   // 빈 줄 출력
    printf("[비교 파일]\n");                        // 비교 파일 섹션 제목
    printf("파일 : %s\n", evidenceFile);            // 비교 파일 경로 출력
    printf("SHA-256 : ");                           // 해시 출력 앞 머리말
    printHash(evidenceHash);                        // 비교 파일 해시를 64자리 16진수로 출력
    printf("\n-----------------------------------------\n"); // 빈 줄 + 구분선 출력

    /* 두 파일의 해시값 비교 */
    if (compareHash(originalHash, evidenceHash))    // 두 해시가 32바이트 모두 같으면
    {                                               // 일치 블록 시작
        printf("[검증 결과]\n");                    // 결과 섹션 제목
        printf("SHA-256 값이 같습니다.\n");         // 해시 일치 메시지
        printf("파일의 무결성이 유지되었습니다.\n"); // 결론: 무결성 유지
    }                                               // 일치 블록 끝
    else                                            // 한 바이트라도 다르면
    {                                               // 불일치 블록 시작
        printf("[검증 결과]\n");                    // 결과 섹션 제목
        printf("SHA-256 값이 다릅니다.\n");         // 해시 불일치 메시지
        printf("파일 내용이 변경되었을 가능성이 있습니다.\n"); // 결론: 변경(위·변조) 가능성
    }                                               // 불일치 블록 끝

    printf("-----------------------------------------\n"); // 마지막 구분선 출력
    return 0;                                       // 정상 종료 코드 0 반환
}                                                   // main 함수 끝
