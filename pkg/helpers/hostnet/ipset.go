package hostnet

import (
	"bytes"
	"fmt"
	"net"
	"os/exec"

	"github.com/coreos/go-iptables/iptables"
	"github.com/golang/glog"
	"sync"

	"github.com/cloudnativelabs/kube-router/pkg/helpers/async_worker"
	"github.com/cloudnativelabs/kube-router/pkg/helpers/tools"
	"strings"
)

const (
	// FamillyInet IPV4.
	FamillyInet = "inet"
	// FamillyInet6 IPV6.
	FamillyInet6 = "inet6"

	// DefaultMaxElem Default OptionMaxElem value.
	DefaultMaxElem = "65536"
	// DefaultHasSize Defaul OptionHashSize value.
	DefaultHasSize = "1024"

	// TypeHashIP The hash:ip set type uses a hash to store IP host addresses (default) or network addresses. Zero valued IP address cannot be stored in a hash:ip type of set.
	TypeHashIP = "hash:ip"
	// TypeHashMac The hash:mac set type uses a hash to store MAC addresses. Zero valued MAC addresses cannot be stored in a hash:mac type of set.
	TypeHashMac = "hash:mac"
	// TypeHashNet The hash:net set type uses a hash to store different sized IP network addresses. Network address with zero prefix size cannot be stored in this type of sets.
	TypeHashNet = "hash:net"
	// TypeHashNetNet The hash:net,net set type uses a hash to store pairs of different sized IP network addresses. Bear in mind that the first parameter has precedence over the second, so a nomatch entry could be potentially be ineffective if a more specific first parameter existed with a suitable second parameter. Network address with zero prefix size cannot be stored in this type of set.
	TypeHashNetNet = "hash:net,net"
	// TypeHashIPPort The hash:ip,port set type uses a hash to store IP address and port number pairs. The port number is interpreted together with a protocol (default TCP) and zero protocol number cannot be used.
	TypeHashIPPort = "hash:ip,port"
	// TypeHashNetPort The hash:net,port set type uses a hash to store different sized IP network address and port pairs. The port number is interpreted together with a protocol (default TCP) and zero protocol number cannot be used. Network address with zero prefix size is not accepted either.
	TypeHashNetPort = "hash:net,port"
	// TypeHashIPPortIP The hash:ip,port,ip set type uses a hash to store IP address, port number and a second IP address triples. The port number is interpreted together with a protocol (default TCP) and zero protocol number cannot be used.
	TypeHashIPPortIP = "hash:ip,port,ip"
	// TypeHashIPPortNet The hash:ip,port,net set type uses a hash to store IP address, port number and IP network address triples. The port number is interpreted together with a protocol (default TCP) and zero protocol number cannot be used. Network address with zero prefix size cannot be stored either.
	TypeHashIPPortNet = "hash:ip,port,net"
	// TypeHashIPMark The hash:ip,mark set type uses a hash to store IP address and packet mark pairs.
	TypeHashIPMark = "hash:ip,mark"
	// TypeHashIPNetPortNet The hash:net,port,net set type behaves similarly to hash:ip,port,net but accepts a cidr value for both the first and last parameter. Either subnet is permitted to be a /0 should you wish to match port between all destinations.
	TypeHashIPNetPortNet = "hash:net,port,net"
	// TypeHashNetIface The hash:net,iface set type uses a hash to store different sized IP network address and interface name pairs.
	TypeHashNetIface = "hash:net,iface"
	// TypeListSet The bitmap:port type uses a memory range to store port numbers.
	TypeBitmapPort = "bitmap:port"
	// TypeListSet The list:set type uses a simple list in which you can store set names.
	TypeListSet = "list:set"

	// TypeListManual The list:set type uses a simple list in which you can store set names.
	TypeManual = "manual"

	// OptionTimeout All set types supports the optional timeout parameter when creating a set and adding entries. The value of the timeout parameter for the create command means the default timeout value (in seconds) for new entries. If a set is created with timeout support, then the same timeout option can be used to specify non-default timeout values when adding entries. Zero timeout value means the entry is added permanent to the set. The timeout value of already added elements can be changed by readding the element using the -exist option. When listing the set, the number of entries printed in the header might be larger than the listed number of entries for sets with the timeout extensions: the number of entries in the set is updated when elements added/deleted to the set and periodically when the garbage colletor evicts the timed out entries.`
	OptionTimeout = "timeout"
	// OptionCounters All set types support the optional counters option when creating a set. If the option is specified then the set is created with packet and byte counters per element support. The packet and byte counters are initialized to zero when the elements are (re-)added to the set, unless the packet and byte counter values are explicitly specified by the packets and bytes options. An example when an element is added to a set with non-zero counter values.
	OptionCounters = "counters"
	// OptionPackets All set types support the optional counters option when creating a set. If the option is specified then the set is created with packet and byte counters per element support. The packet and byte counters are initialized to zero when the elements are (re-)added to the set, unless the packet and byte counter values are explicitly specified by the packets and bytes options. An example when an element is added to a set with non-zero counter values.
	OptionPackets = "packets"
	// OptionBytes All set types support the optional counters option when creating a set. If the option is specified then the set is created with packet and byte counters per element support. The packet and byte counters are initialized to zero when the elements are (re-)added to the set, unless the packet and byte counter values are explicitly specified by the packets and bytes options. An example when an element is added to a set with non-zero counter values.
	OptionBytes = "bytes"
	// OptionComment All set types support the optional comment extension. Enabling this extension on an ipset enables you to annotate an ipset entry with an arbitrary string. This string is completely ignored by both the kernel and ipset itself and is purely for providing a convenient means to document the reason for an entry's existence. Comments must not contain any quotation marks and the usual escape character (\) has no meaning
	OptionComment = "comment"
	// OptionSkbinfo All set types support the optional skbinfo extension. This extension allow to store the metainfo (firewall mark, tc class and hardware queue) with every entry and map it to packets by usage of SET netfilter target with --map-set option. skbmark option format: MARK or MARK/MASK, where MARK and MASK are 32bit hex numbers with 0x prefix. If only mark is specified mask 0xffffffff are used. skbprio option has tc class format: MAJOR:MINOR, where major and minor numbers are hex without 0x prefix. skbqueue option is just decimal number.
	OptionSkbinfo = "skbinfo"
	// OptionSkbmark All set types support the optional skbinfo extension. This extension allow to store the metainfo (firewall mark, tc class and hardware queue) with every entry and map it to packets by usage of SET netfilter target with --map-set option. skbmark option format: MARK or MARK/MASK, where MARK and MASK are 32bit hex numbers with 0x prefix. If only mark is specified mask 0xffffffff are used. skbprio option has tc class format: MAJOR:MINOR, where major and minor numbers are hex without 0x prefix. skbqueue option is just decimal number.
	OptionSkbmark = "skbmark"
	// OptionSkbprio All set types support the optional skbinfo extension. This extension allow to store the metainfo (firewall mark, tc class and hardware queue) with every entry and map it to packets by usage of SET netfilter target with --map-set option. skbmark option format: MARK or MARK/MASK, where MARK and MASK are 32bit hex numbers with 0x prefix. If only mark is specified mask 0xffffffff are used. skbprio option has tc class format: MAJOR:MINOR, where major and minor numbers are hex without 0x prefix. skbqueue option is just decimal number.
	OptionSkbprio = "skbprio"
	// OptionSkbqueue All set types support the optional skbinfo extension. This extension allow to store the metainfo (firewall mark, tc class and hardware queue) with every entry and map it to packets by usage of SET netfilter target with --map-set option. skbmark option format: MARK or MARK/MASK, where MARK and MASK are 32bit hex numbers with 0x prefix. If only mark is specified mask 0xffffffff are used. skbprio option has tc class format: MAJOR:MINOR, where major and minor numbers are hex without 0x prefix. skbqueue option is just decimal number.
	OptionSkbqueue = "skbqueue"
	// OptionHashSize This parameter is valid for the create command of all hash type sets. It defines the initial hash size for the set, default is 1024. The hash size must be a power of two, the kernel automatically rounds up non power of two hash sizes to the first correct value.
	OptionHashSize = "hashsize"
	// OptionMaxElem This parameter is valid for the create command of all hash type sets. It does define the maximal number of elements which can be stored in the set, default 65536.
	OptionMaxElem = "maxelem"
	// OptionFamilly This parameter is valid for the create command of all hash type sets except for hash:mac. It defines the protocol family of the IP addresses to be stored in the set. The default is inet, i.e IPv4.
	OptionFamilly = "family"
	// OptionNoMatch The hash set types which can store net type of data (i.e. hash:*net*) support the optional nomatch option when adding entries. When matching elements in the set, entries marked as nomatch are skipped as if those were not added to the set, which makes possible to build up sets with exceptions. See the example at hash type hash:net below. When elements are tested by ipset, the nomatch flags are taken into account. If one wants to test the existence of an element marked with nomatch in a set, then the flag must be specified too.
	OptionNoMatch = "nomatch"
	// OptionForceAdd All hash set types support the optional forceadd parameter when creating a set. When sets created with this option become full the next addition to the set may succeed and evict a random entry from the set.
	OptionForceAdd = "forceadd"
)

const (
	TmpTableSuffix       = "-"
	VRaw           Proto = 255
	asyncQueueSize       = 5
)

var protoRelatedOptions = []string{OptionFamilly, FamillyInet6, FamillyInet, TypeManual}

var perProtocolNamePrefix = map[Proto]string{
	V4:   "v4:",
	V6:   "v6:",
	VRaw: "",
}

var bufferPool = sync.Pool{New: func() interface{} {
	return &bytes.Buffer{}
}}

// IPSet represent ipset sets managed by.
type IPSet struct {
	Sets map[string]*Set
}

type EntriesMapType map[uint32]*Entry
type PerProtoEntryMapType map[Proto]EntriesMapType

// Set reprensent a ipset set entry.
type Set struct {
	sync.Mutex

	Parent   *IPSet
	Name     string
	Entries  PerProtoEntryMapType
	Options  []string
	isManual bool
	exists   bool
}

// Entry of ipset Set.
type Entry struct {
	Set     *Set
	Options []string
}

type requestType struct {
	set          *Set
	entries      interface{}
	extraOptions []string
}

type asyncDataChannelType struct {
	fn func(*requestType) error
	*requestType
}

var asyncDataChannel chan asyncDataChannelType

type asyncIpSetWorker struct {
	async_worker.Worker
	dataChannel chan asyncDataChannelType
}

func init() {
	asyncDataChannel = make(chan asyncDataChannelType, asyncQueueSize)
	async_worker.GlobalManager.AddWorkerRoutine(&asyncIpSetWorker{dataChannel: asyncDataChannel}, "IpSet bg worker")
}

// Used to run ipset binary with args and return stdout.
func (ipset *IPSet) run(namePos int, args ...string) (string, error) {
	return ipset.runWithStdin(nil, namePos, args...)
}

// Used to run ipset binary with arg and inject stdin buffer and return stdout.
func (ipset *IPSet) runWithStdin(stdin *bytes.Buffer, namePos int, args ...string) (string, error) {
	var err error
	var stderr = bufferPool.Get().(*bytes.Buffer)
	var stdout = bufferPool.Get().(*bytes.Buffer)
	cmd := exec.Cmd{
		Path:   tools.GetExecPath("ipset"),
		Args:   append([]string{tools.GetExecPath("ipset")}, args...),
		Stderr: stderr,
		Stdout: stdout,
	}

	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin.Bytes())
	}

	if err = cmd.Run(); err != nil {
		err = tools.NewErrorf("error: %s\nfailed cmd: %s\nstdin: %s", stderr.String(),
			strings.Join(cmd.Args, " "), stdin.String())
	}
	// manipulating ipset(s) can be costly (long). that's why repetitive calls to ipset.Create() etc
	// were replaced by GetOrCreate() (this assuming that original intention to call Create() repetitively
	// was to make sure that ipset will be recreated if between the cycles disappeared from the system)
	// GetOrCreate will just return existing ipset, or create new, if doesn't exists. By such change
	// we would lose the fix (recreation) if on broken / missing ipsets.
	// So here in case and only in that case of getting back error from ipset command about missing ipset,
	// we silently recreate it (with the options it is created original upon initial Create() and we rerun the command
	if err != nil && namePos != 0 && strings.Contains(err.Error(), "does not exist") {
		var name string
		if strings.Contains(err.Error(), "the second set does not exist") {
			namePos += 1
		}
		if name, _ = getNameAndProto(args[namePos]); name == "" {
			name = args[namePos]
		}
		if err = ipset.Sets[name].Create(); err == nil {
			return ipset.runWithStdin(stdin, 0, args...)
		}
	}

	if err != nil {
		return "ipset call failed", err
	}

	return stdout.String(), nil
}

// NewIPSet create a new IPSet with IpSetPath initialized.
func NewIPSet() *IPSet {
	ipSet := &IPSet{
		Sets: make(map[string]*Set),
	}
	return ipSet
}

// Create a set identified with setname and specified type. The type may
// require type specific options. Does not create set on the system if it
// already exists by the same name.
func (ipset *IPSet) Create(setName string, createOptions ...string) (*Set, error) {
	// Populate Set map if needed
	if ipset.Get(setName) == nil {
		ipset.Sets[setName] = &Set{
			Name:     setName,
			Options:  removeFamily(createOptions),
			Parent:   ipset,
			Entries:  make(PerProtoEntryMapType),
			isManual: tools.CheckForElementInArray(TypeManual, createOptions),
		}
	}

	// Determine if set with the same name is already active on the system
	if err := ipset.Sets[setName].Create(); err != nil {
		return nil, fmt.Errorf("Failed to create ipset %s: %s",
			setName, err.Error())
	}
	ipset.Sets[setName].exists = true
	return ipset.Sets[setName], nil
}

func (set *Set) create(p Proto, options ...string) error {
	_, err := set.Parent.run(1, append([]string{"create", set.name(p)}, set.fixOptions(p, options)...)...)
	if err != nil {
		return fmt.Errorf("Failed to create ipset set on system: %s", err)
	}
	return nil
}

func entryRecordsSplitter(r rune) bool {
	return r == '-' || r == ','
}

func (entry *Entry) getProtocol() Proto {
	return NewIP(strings.FieldsFunc(entry.Options[0], entryRecordsSplitter)[0]).Protocol()
}

// Destroy the specified set or all the sets if none is given. If the set has
// got reference(s), nothing is done and no set destroyed.
func (set *Set) Destroy(*requestType) error {
	_, _ = set.Parent.run(0, "destroy", set.Name)
	for p := range UsedTcpProtocols {
		_, err := set.Parent.run(0, "destroy", set.name(p))
		if err != nil && !strings.Contains(err.Error(), "not exist") {
			glog.Errorf("%s - %s", set.name(p), err.Error())
		}
	}
	if !strings.HasSuffix(set.Name, TmpTableSuffix) {
		set.Parent.Destroy(set.Name + TmpTableSuffix)
	}
	set.Parent.Sets[set.Name] = nil
	delete(set.Parent.Sets, set.Name)
	return nil
}

// Destroy the specified set by name. If the set has got reference(s), nothing
// is done and no set destroyed. If the IPSet does not contain the named set
// then Destroy is a no-op.
func (ipset *IPSet) Destroy(setName string) error {
	set := ipset.Get(setName)
	if set == nil {
		return nil
	}

	err := set.Destroy(nil)
	if err != nil {
		return err
	}

	return nil
}

// DestroyAllWithin destroys all sets contained within the IPSet's Sets.
func (ipset *IPSet) DestroyAllWithin() error {
	for _, v := range ipset.Sets {
		err := v.Destroy(nil)
		if err != nil {
			return err
		}
	}

	return nil
}

// IsActive checks if a set exists on the system with the same name.
func (set *Set) IsActive(p Proto) (exists bool, err error) {
	if _, err = set.Parent.run(0, "list", "-name", set.name(p)); err != nil &&
		!strings.Contains(err.Error(), "does not exist") {
		return false, err
	}
	return err == nil, nil
}

func (set *Set) Create() (err error) {
	err = UsedTcpProtocols.ForEach(func(p Proto) error {
		if is, err := set.createForProto(p, true); !is || err != nil {
			return err
		}
		return nil
	})
	if set.isManual {
		return nil
	}
	return set.createUnionSet()
}

// IsActive checks if a set exists on the system with the same name.
func (set *Set) createForProto(p Proto, args ...bool) (exists bool, err error) {
	var create = len(args) > 0 && args[0] == true

	if exists, err = set.IsActive(p); !exists && create {
		err = set.create(p, set.Options...)
	}
	if err == nil {
		exists = true
	}
	return exists, err
}

func (set *Set) createUnionSet() (err error) {
	var out string
	var create bool
	var handler, _ = iptables.New()

	if out, err = set.Parent.run(0, "list", "-t", set.Name); err != nil &&
		!strings.Contains(err.Error(), "name does not exist") {
		return err
	} else if err != nil {
		create = true
	} else if !strings.Contains(out, "Type: list:set") {
		create = true
		IptablesCleanRule(handler, V4, IpTablesCleanupRuleType{RuleContaining: []string{set.Name}}, true)
		if _, err = set.Parent.run(0, "destroy", set.Name); err != nil {
			return fmt.Errorf("incompatible ipset type found for \"%s\" and set can't by recreated - manual cleanup needed", set.Name)
		}
	}
	if create {
		_, err = set.Parent.run(0, "create", set.Name, "list:set")
	}
	if err == nil {
		_, err = set.Parent.run(0, "add", "-exist", set.Name, set.name(V4))
	}
	if err == nil {
		_, err = set.Parent.run(0, "add", "-exist", set.Name, set.name(V6))
	}
	return err
}

func (set *Set) getActiveProtocols() ProtocolMapType {
	if set.isManual {
		return ProtocolMapType{VRaw: true}
	}

	var pt = ProtocolMapType{}
	for key := range set.Entries {
		pt[key] = true
		if len(pt) == len(UsedTcpProtocols) {
			return pt
		}
	}
	if len(pt) == 0 {
		return UsedTcpProtocols
	}
	return pt
}

func getSystemName(p Proto, name string) string {
	return perProtocolNamePrefix[p] + name
}

func (set *Set) name(p Proto) string {
	if set.isManual {
		return set.Name
	}
	return getSystemName(p, set.Name)
}

func removeFamily(options []string) []string {
	newOptions := make([]string, 0)
	for _, o := range options {
		if tools.CheckForElementInArray(o, protoRelatedOptions) {
			continue
		}
		newOptions = append(newOptions, o)
	}
	return newOptions
}

func (set *Set) fixOptions(p Proto, options []string) []string {
	newOptions := removeFamily(options)
	return set.addFamily(p, newOptions)
}

func (set *Set) addFamily(p Proto, options []string) []string {
	if set.isManual {
		return options
	}
	newOptions := append(options, OptionFamilly)
	if p == V6 {
		return append(newOptions, FamillyInet6)
	}
	return append(newOptions, FamillyInet)
}

// Parse ipset save stdout.
// ex:
// create KUBE-DST-3YNVZWWGX3UQQ4VQ hash:ip family inet hashsize 1024 maxelem 65536 timeout 0
// add KUBE-DST-3YNVZWWGX3UQQ4VQ 100.96.1.6 timeout 0
func parseIPSetSave(ipset *IPSet, result string) map[string]*Set {
	sets := make(map[string]*Set)
	// Save is always in order
	lines := strings.Split(result, "\n")
	for _, line := range lines {
		content := strings.Split(line, " ")
		if len(content) < 2 {
			continue
		}
		name, proto := getNameAndProto(content[1])
		if name == "" {
			if sets[content[1]] != nil {
				sets[content[1]].exists = true
			}
			continue
		}
		if content[0] == "create" && sets[name] == nil {
			sets[name] = &Set{
				Parent:  ipset,
				Name:    name,
				Options: removeFamily(content[2:]),
			}
			sets[name].Entries = make(PerProtoEntryMapType)
		} else if content[0] == "add" {
			set := sets[name]
			set.Entries.Add(proto, &Entry{set, content[2:]})
		}
	}

	return sets
}

func getNameAndProto(s string) (string, Proto) {
	set := strings.Split(s, ":")
	if len(set) < 2 {
		return "", V4
	}
	if set[0] == "v4" {
		return set[1], V4
	}
	return set[1], V6
}

// Build ipset restore input
// ex:
// create KUBE-DST-3YNVZWWGX3UQQ4VQ hash:ip family inet hashsize 1024 maxelem 65536 timeout 0
// add KUBE-DST-3YNVZWWGX3UQQ4VQ 100.96.1.6 timeout 0
func (set *Set) buildIPSetRestore(buf *bytes.Buffer) *bytes.Buffer {
	for p := range *UsedTcpProtocols.Copy().Merge(&ProtocolMapType{VRaw: true}) {
		fmt.Fprintf(buf, "create %s %s\n", set.name(p), strings.Join(set.addFamily(p, set.Options)[:], " "))
		for _, entry := range set.Entries[p] {
			fmt.Fprintf(buf, "add %s %s\n", set.name(p), strings.Join(entry.Options[:], " "))
		}
	}
	return buf
}

// multi-family wrapper to base Set/IPSet methods.
// it takes the method as parameter and runs it for both protocol families, with
// adapted setName (name prefix) or options ( inet/inet6 family opt )
func (set *Set) perProtoMethodWrapper(f func(Proto, ...interface{}) error, args ...interface{}) (err error) {
	return set.getActiveProtocols().ForEach(func(p Proto) error {
		return f(p, args...)
	})
}

// Save the given set, or all sets if none is given to stdout in a format that
// restore can read. The option -file can be used to specify a filename instead
// of stdout.
// save "ipset save" command output to ipset.sets.
func (ipset *IPSet) Save() error {
	stdout, err := ipset.run(0, "save")
	if err != nil {
		glog.Errorf("Failed loading existing IPSets: %s", err.Error())
		return err
	}
	ipset.Sets = parseIPSetSave(ipset, stdout)
	return nil
}

func (ipset *IPSet) SaveSimpleList() (*map[string]*Set, error) {
	stdout, err := ipset.run(0, "list", "-name")
	if err != nil {
		return nil, err
	}

	var simpleIPSet = IPSet{Sets: make(map[string]*Set)}
	lines := strings.Split(stdout, "\n")
	for _, line := range lines {
		name, _ := getNameAndProto(line)
		if name == "" {
			name = line
		}
		if name == "" || simpleIPSet.Sets[name] != nil {
			continue
		}
		simpleIPSet.Sets[name] = &Set{
			Parent: ipset,
			Name:   name,
		}
	}
	return &simpleIPSet.Sets, nil
}

// Restore a saved session generated by save. The saved session can be fed from
// stdin or the option -file can be used to specify a filename instead of
// stdin. Please note, existing sets and elements are not erased by restore
// unless specified so in the restore file. All commands are allowed in restore
// mode except list, help, version, interactive mode and restore itself.
// Send formated ipset.sets into stdin of "ipset restore" command.
func (ipset *IPSet) Restore() (err error) {
	var buf = bufferPool.Get().(*bytes.Buffer)
	for _, set := range ipset.Sets {
		set.buildIPSetRestore(buf)
	}
	return ipset._restore(buf)
}

func (set *Set) Restore() error {
	return set.Parent._restore(set.buildIPSetRestore(bufferPool.Get().(*bytes.Buffer)))
}

func (ipset *IPSet) _restore(buf *bytes.Buffer) error {
	_, err := ipset.runWithStdin(buf, 0, "restore", "-exist")
	buf.Reset()
	bufferPool.Put(buf)
	if err != nil {
		return err
	}
	return nil
}

// Flush all entries from the specified set or flush all sets if none is given.
func (set *Set) Flush() error {
	return set.perProtoMethodWrapper(set._flush)
}

func (set *Set) _flush(p Proto, args ...interface{}) error {
	_, err := set.Parent.run(1, "flush", set.name(p))
	if err != nil {
		return err
	}
	return nil
}

// Flush all entries from the specified set or flush all sets if none is given.
func (ipset *IPSet) Flush() error {
	for _, s := range ipset.Sets {
		if err := s.Flush(); err != nil {
			return err
		}
	}
	return nil
}

func (ipset *IPSet) GetOrCreate(setName string, options ...string) (set *Set, err error) {
	if set = ipset.Sets[setName]; set == nil || !set.exists {
		return ipset.Create(setName, options...)
	}
	return
}

// Get Set by Name.
func (ipset *IPSet) Get(setName string) *Set {
	set, ok := ipset.Sets[setName]
	if !ok {
		return nil
	}

	return set
}

// Rename a set. Set identified by SETNAME-TO must not exist.
func (set *Set) Rename(newName string) error {
	return set.perProtoMethodWrapper(set._rename, newName)
}

func (set *Set) _rename(p Proto, args ...interface{}) error {
	_, err := set.Parent.run(1, "rename", set.name(p), args[0].(string))
	if err != nil {
		return err
	}
	return nil
}

// Swap the content of two sets, or in another words, exchange the name of two
// sets. The referred sets must exist and compatible type of sets can be
// swapped only.
func (set *Set) swap(setTo *Set) error {
	return set.perProtoMethodWrapper(set._swap, setTo.Name)
}

func (set *Set) _swap(p Proto, args ...interface{}) (err error) {
	swapWith := args[0].(string)
	_, err = set.Parent.run(1, "swap", set.name(p), getSystemName(p, swapWith))
	return err
}

func (set *Set) Append(options ...string) *Entry {
	if len(options) < 1 || options[0] == "" {
		return nil
	}
	entry := &Entry{
		Set:     set,
		Options: options,
	}
	return set.Entries.Add(entry.getProtocol(), entry)
}

func (e PerProtoEntryMapType) Add(proto Proto, entry *Entry) *Entry {
	if e[proto] == nil {
		e[proto] = make(EntriesMapType)
	}
	hash := tools.GetHash(fmt.Sprint(entry.Options))
	if e[proto][hash] != nil {
		return nil
	}
	e[proto][hash] = entry
	return entry
}

func (set *Set) getTmpSet() *Set {
	return &Set{
		Parent:   set.Parent,
		Name:     set.Name + TmpTableSuffix,
		Options:  set.Options,
		Entries:  make(PerProtoEntryMapType),
		isManual: set.isManual,
	}
}

func (set *Set) Prepare(entries interface{}) *Set {
	tmpSet := set.getTmpSet()

	switch eTyped := entries.(type) {
	case []string:
		for _, e := range eTyped {
			tmpSet.Append(e)
		}
	case [][]string:
		for _, e := range eTyped {
			tmpSet.Append(e...)
		}
	case []*net.IPNet:
		for _, e := range eTyped {
			if !e.IP.Equal(net.IP{}) {
				tmpSet.Append(e.IP.String())
			}
		}
	case PerProtoEntryMapType:
		tmpSet.Entries = eTyped
	default:
		tmpSet.Flush()
		glog.Errorf("IPSet refresh: Unknown type while reading records for IPSet %s, %T", set.Name, entries)
	}

	return tmpSet
}

func (set *Set) CommitWithSet(tmpSet *Set) (err error) {
	err = tmpSet.Restore()

	if err == nil {
		set.Entries = tmpSet.Entries
		err = tmpSet.swap(set)
	}

	if err == nil {
		err = tmpSet.Flush()
	}
	return
}

// Refresh a Set with new entries.
//func (set *Set) _refresh(entries interface{}, extraOptions ...string) (err error) {
func (set *Set) refresh(in *requestType) (err error) {
	set.Lock()
	defer set.Unlock()
	return set.CommitWithSet(set.Prepare(in.entries))
}

func (set *Set) Commit() error {
	return set.RefreshWithEntries(set.Entries)
}

// Refresh a Set with new entries.
func (set *Set) Refresh(entries interface{}, extraOptions ...string) (err error) {
	return set.refresh(&requestType{set, entries, extraOptions})
}

// Refresh a Set with new entries with built-in options.
func (set *Set) RefreshWithBuiltinOptions(entries [][]string) (err error) {
	return set.Refresh(entries)
}

func (set *Set) RefreshWithEntries(entries PerProtoEntryMapType) error {
	return set.Refresh(entries)
}

func (bw *asyncIpSetWorker) StopWorker() {
	close(bw.dataChannel)
}

func (bw *asyncIpSetWorker) StartWorker() {
	go bw.backgroundWorker()
}

func (bw *asyncIpSetWorker) backgroundWorker() {
	for data := range bw.dataChannel {
		if err := data.fn(data.requestType); err != nil {
			glog.Errorf("Failed to update %s: %s", data.set.Name, err)
		}
	}
	glog.V(3).Infof("%s done", bw.GetName())
	bw.Done()
}

func (set *Set) RefreshAsync(entries interface{}, extraOptions ...string) {
	if set != nil {
		asyncDataChannel <- asyncDataChannelType{set.refresh,
			&requestType{set, entries, extraOptions}}
	}
}
