/* Host tests for linekit (components/mp_linekit/mp_linekit.c), exercising
 * mp_line_read over a real socketpair: echo, backspace, IAC stripping,
 * timeout. The socketpair is wrapped in an fd-backed mp_conn shim, the
 * same contract the lwIP backend implements on target. */
#include <errno.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "test_util.h"

#include "mp_linekit.h"

static int shim_recv(mp_conn_t *c, void *buf, size_t len, uint32_t timeout_ms)
{
    int fd = (int)(intptr_t)c->ctx;
    struct timeval tv = {
        .tv_sec = (time_t)(timeout_ms / 1000),
        .tv_usec = (suseconds_t)(timeout_ms % 1000) * 1000,
    };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ssize_t r = recv(fd, buf, len, 0);
    if (r > 0) {
        return (int)r;
    }
    if (r == 0) {
        return 0;
    }
    return (errno == EAGAIN || errno == EWOULDBLOCK) ? MP_CONN_TIMEOUT
                                                     : MP_CONN_ABORTED;
}

static int shim_send(mp_conn_t *c, const void *buf, size_t len)
{
    int fd = (int)(intptr_t)c->ctx;
    return send(fd, buf, len, MSG_NOSIGNAL) == (ssize_t)len ? 0 : -1;
}

static void shim_release(mp_conn_t *c)
{
    close((int)(intptr_t)c->ctx);
}

static const mp_conn_ops_t s_shim_ops = {
    .recv = shim_recv,
    .send = shim_send,
    .shutdown = NULL,
    .release = shim_release,
};

static mp_conn_t s_conn;

static int make_pair(int fds[2])
{
    int r = socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
    s_conn.ops = &s_shim_ops;
    s_conn.ctx = (void *)(intptr_t)fds[0];
    return r;
}

#define CONN (&s_conn)

static void test_cmd_lookup(void)
{
    static const mp_cmd_t cmds[] = {
        { "id", "uid=0(root)\r\n" },
        { "cat ", "canned cat reply\r\n" },
        { "ls", "bin etc\r\n" },
    };
    const mp_cmd_t *c = mp_cmd_lookup(cmds, 3, "id");
    CHECK(c && c->cmd == cmds[0].cmd);
    /* exact wins over prefix */
    c = mp_cmd_lookup(cmds, 3, "ls");
    CHECK(c && c->cmd == cmds[2].cmd);
    /* prefix match */
    c = mp_cmd_lookup(cmds, 3, "cat /etc/passwd");
    CHECK(c && c->cmd == cmds[1].cmd);
    /* unknown */
    CHECK(mp_cmd_lookup(cmds, 3, "nmap") == NULL);
    CHECK(mp_cmd_lookup(NULL, 3, "id") == NULL);
}

static void test_read_plain_no_echo(void)
{
    int fds[2];
    CHECK(make_pair(fds) == 0);
    write(fds[1], "admin\r\n", 7);

    char buf[32];
    int n = mp_line_read(CONN, buf, sizeof(buf), 1000, false, MP_LINE_ECHO_OFF);
    CHECK(n == 5);
    CHECK_STR(buf, "admin");

    char echoed[8] = { 0 };
    ssize_t r = recv(fds[1], echoed, sizeof(echoed), MSG_DONTWAIT);
    CHECK(r <= 0); /* nothing echoed in password mode */
    close(fds[0]); close(fds[1]);
}

static void test_read_echo_and_backspace(void)
{
    int fds[2];
    CHECK(make_pair(fds) == 0);
    write(fds[1], "idx\x7f\n", 5); /* 'i','d','x',DEL,NL -> "id" */

    char buf[32];
    int n = mp_line_read(CONN, buf, sizeof(buf), 1000, false, MP_LINE_ECHO_ON);
    CHECK(n == 2);
    CHECK_STR(buf, "id");

    char echoed[16] = { 0 };
    ssize_t r = recv(fds[1], echoed, sizeof(echoed), 0);
    CHECK(r == 8); /* i d x "\b \b" \r\n */
    CHECK(memcmp(echoed, "idx\b \b\r\n", 8) == 0);
    close(fds[0]); close(fds[1]);
}

static void test_read_strips_iac(void)
{
    int fds[2];
    CHECK(make_pair(fds) == 0);
    /* IAC WILL ECHO, IAC SB x SE, then "id\r\n" */
    const unsigned char stream[] = {
        255, 251, 1,
        255, 250, 'a', 'b', 255, 240,
        'i', 'd', '\r', '\n',
    };
    write(fds[1], stream, sizeof(stream));

    char buf[32];
    int n = mp_line_read(CONN, buf, sizeof(buf), 1000, true, MP_LINE_ECHO_OFF);
    CHECK(n == 2);
    CHECK_STR(buf, "id");
    close(fds[0]); close(fds[1]);
}

static void test_read_timeout_and_close(void)
{
    int fds[2];
    CHECK(make_pair(fds) == 0);

    char buf[32];
    int n = mp_line_read(CONN, buf, sizeof(buf), 100, false, MP_LINE_ECHO_OFF);
    CHECK(n == -2); /* timed out */

    close(fds[1]);
    n = mp_line_read(CONN, buf, sizeof(buf), 1000, false, MP_LINE_ECHO_OFF);
    CHECK(n == -1); /* peer closed */
    close(fds[0]);
}

static void test_send_all(void)
{
    int fds[2];
    CHECK(make_pair(fds) == 0);
    CHECK(mp_send_str(CONN, "hello") == 0);
    CHECK(mp_send_str(CONN, NULL) == 0); /* no-op */
    char buf[8] = { 0 };
    CHECK(recv(fds[1], buf, sizeof(buf), 0) == 5);
    CHECK_STR(buf, "hello");
    close(fds[1]);
    CHECK(mp_send_str(CONN, "x") == -1); /* peer gone */
    close(fds[0]);
}

int main(void)
{
    test_cmd_lookup();
    test_read_plain_no_echo();
    test_read_echo_and_backspace();
    test_read_strips_iac();
    test_read_timeout_and_close();
    test_send_all();
    TEST_SUMMARY("test_linekit");
}
