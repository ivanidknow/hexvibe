// Vulnerable: VUL-CVE-2020-22026
double depth;
    double *table;
    int index;
} TremoloContext;
...
        src += channels;
        s->index++;
        if (s->index >= inlink->sample_rate / s->freq)
            s->index = 0;
    }
...
...
    for (i = 0; i < inlink->sample_rate / s->freq; i++) {
        double env = s->freq * i / inlink->sample_rate;
        env = sin(2 * M_PI * fmod(env + 0.25, 1.0));
