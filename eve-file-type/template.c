#include <stdio.h>
#include <stdlib.h>

#include "suricata-plugin.h"
#include "util-mem.h"
#include "util-debug.h"

#define OUTPUT_NAME "threaded-filetype-plugin"
#define MAX_THREADS 64

struct Context;

/*
 * Per thread context tracking file pointer
 */
typedef struct ThreadContext_ {
    FILE *fp;
    struct Context_ *context;
} ThreadContext;

typedef struct Context_ {
    const char *log_dir;
    const char *append;
    const char *filename;
    bool threaded;
    FILE *fp;
    ThreadContext threads[MAX_THREADS];
} Context;

static int Write(const char *buffer, int buffer_len, void *ctx, void *thread_ctx) {
    Context *context = ctx;
    FILE *fp;
    if (context->threaded) {
        ThreadContext *tctx = thread_ctx;
        fp = tctx->fp;
    } else {
        fp = context->fp;
    }
    if (!fp) {
        return -1;
    }

    int ret = 1 == fwrite(buffer, buffer_len, 1, fp);
    if (ret)
        ret = 1 == fwrite("\n", 1, 1, fp);
    return ret == 1 ? 0 : -1;
}

static void Close(void *ctx) {
    if (!ctx) {
        return;
    }

    SCLogDebug("[ctx: %p]", ctx);
    Context *context = ctx;
    if (context->fp) {
        fclose(context->fp);
    }
    SCFree(ctx);
}

static FILE *ThreadedOpenFile(Context *context, int thread_id)
{
    char actual_filename[1024];
    const char *base = SCBasename(context->filename);
    if (thread_id == -1) {
        snprintf(actual_filename, 1023, "%s/%s", context->log_dir, base);
    } else {
        char *tmp = strdup(base);
        char *dot = strrchr(tmp, '.');
        if (dot) {
            tmp[dot-tmp] = '\0';
            snprintf(actual_filename, 1023, "%s/%*s.%d.%s", context->log_dir, (int) (dot - tmp), tmp, thread_id, dot+1);
        } else {
            snprintf(actual_filename, 1023, "%s/%s.%d", context->log_dir,  tmp, thread_id);
        }
        free(tmp);
    }
    SCLogNotice("thread_id=%d; actual_filename %s", thread_id, actual_filename);
    return fopen(actual_filename, strcmp(context->append, "yes") == 0 ? "a": "w");
}

#define DEFAULT_APPEND "yes"
#define DEFAULT_FILENAME "eve.plugin.json"

static int Init(ConfNode *conf, bool threaded, void **data) {

    Context *context = SCCalloc(1, sizeof(Context));
    if (context == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Unable to allocate file plugin context");
        return -1;
    }

    if (ConfGet("default-log-dir", &context->log_dir) == 0) 
        context->log_dir = DEFAULT_LOG_DIR;
    if (ConfGet("append", &context->append) == 0) 
        context->append = DEFAULT_APPEND;
    if (ConfGet("filename", &context->filename) == 0) 
        context->filename = DEFAULT_FILENAME;

    SCLogNotice("log_dir: %s, append: %s, filename: %s, threaded: %d",
             context->log_dir, context->append, context->filename, context->threaded);

    context->threaded = threaded;
    if (!context->threaded) {
        context->fp = ThreadedOpenFile(context, -1);
        if (context->fp == NULL) {
            SCFree(context);
            SCLogError(SC_ERR_OPENING_FILE, "Unable to open file");
            return -1;
        }
    }
    *data = context;
    return 0;
}

static int ThreadInit(void *ctx, int thread_id, void **thread_ctx)
{
    SCLogNotice("Entering [thread %d; ctx: %p] %p", thread_id, ctx, thread_ctx);
    Context *context = ctx;
    if (context->threads[thread_id].context == NULL) {
        context->threads[thread_id].fp = ThreadedOpenFile(context, thread_id);
        if (context->threads[thread_id].fp == NULL) {
            SCLogError(SC_ERR_OPENING_FILE, "Unable to open file");
            goto error_exit;
        }
        context->threads[thread_id].context = context;
    }
    *thread_ctx = &context->threads[thread_id];
    return 0;

error_exit:
    *thread_ctx = NULL;
    return -1;
}

static int ThreadDeinit(void *ctx, void *thread_ctx)
{
    ThreadContext *tctx = thread_ctx;
    if (tctx && tctx->context != NULL) {
        SCLogDebug("Entering [ctx: %p; thread_ctx: %p]", ctx, thread_ctx);
        if (tctx->fp) {
            fclose(tctx->fp);
            tctx->fp = NULL;
        }
        tctx->context = NULL;
    }
}

/**
 * Called by Suricata to initialize the module. This module registers
 * the new file type to the JSON logger.
 */
void PluginInit(void)
{
    SCPluginFileType *my_output = SCCalloc(1, sizeof(SCPluginFileType));
    if (my_output == NULL) {
        FatalError(SC_ERR_MEM_ALLOC, "Unable to allocate plugin memory for %s", OUTPUT_NAME);
    }
    my_output->name = OUTPUT_NAME;
    my_output->Init = Init;
    my_output->Close = Close;
    my_output->Write = Write;
    my_output->ThreadInit = ThreadInit;
    my_output->ThreadDeinit = ThreadDeinit;
    if (!SCPluginRegisterFileType(my_output)) {
        FatalError(SC_ERR_PLUGIN, "Failed to register filetype plugin: %s", OUTPUT_NAME);
    }
}

const SCPlugin PluginRegistration = {
    .name = OUTPUT_NAME,
    .author = "Jeff Lucovsky",
    .license = "BSD",
    .Init = PluginInit,
};

const SCPlugin *SCPluginRegister()
{
    return &PluginRegistration;
}
