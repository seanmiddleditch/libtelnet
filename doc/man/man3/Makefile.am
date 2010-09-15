MANPAGES = \
	libtelnet.h.3 \
	telnet_environ_t.3 \
	telnet_event_t.3 \
	telnet_event_t_compress_t.3 \
	telnet_event_t_data_t.3 \
	telnet_event_t_environ_t.3 \
	telnet_event_t_error_t.3 \
	telnet_event_t_iac_t.3 \
	telnet_event_t_negotiate_t.3 \
	telnet_event_t_subnegotiate_t.3 \
	telnet_event_t_ttype_t.3 \
	telnet_event_t_zmp_t.3 \
	telnet_event_t_mssp_t.3 \
	telnet_telopt_t.3

$(MANPAGES): build-stamp

CLEANFILES = $(MANPAGES) build-stamp

build-stamp: ../../../libtelnet.h ../../../Doxyfile
	( cd "$(top_builddir)" ; $(PATH_DOXYGEN) )
	touch "$@"

if BUILD_DOCS
man3_MANS = $(MANPAGES)
endif
